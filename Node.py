import threading
import time
import logging
import raft_definitions
from raft_definitions import STATUSES, Raft, IP

logging_format = '%(asctime)-15s [%(threadName)s] - [%(funcName)s] %(message)s'
level = logging.DEBUG  # Change to Error or something like that to silence the log to file!
logging.basicConfig(filename='log.log', level=level, format=logging_format)
logger = logging.getLogger()


class Node(object):
    def __init__(self, nodes, ip):
        self.address = ip
        self.nodes = nodes
        self.lock = threading.Lock()
        self.log = []
        self.staged = None
        self.term = 0
        self.status = STATUSES['follower']  # starting as follower
        self.majority = ((len(self.nodes) + 1) // 2) + 1
        self.voteCount = 0
        self.commitIndex = 0
        self.timeout_thread = None
        self.init_timeout()  # starting as follower, we need to start the timeout

        self.election_time = time.time()
        self.leader = None

    def start_election(self):
        logger.debug("{} starting election; status: {}, term:{}".format(self.address, self.status, self.term))
        self.term += 1
        self.voteCount = 0
        self.status = STATUSES['candidate']
        self.init_timeout()
        self.increment_vote()
        self.send_vote_req()

    def send_vote_req(self):
        # we continue to ask to vote to the address that haven't voted yet
        # till everyone has voted
        # or I am the leader
        for voter_ip in self.nodes:
            threading.Thread(target=self.ask_for_vote,
                             args=(voter_ip, self.term)).start()

    def ask_for_vote(self, voter_ip, term):
        # need to include self.commitIndex, only up-to-date candidate could win
        print("{} ASKING FOR VOTE".format(self.address))

        command = raft_definitions.COMMANDS['RequestVote']
        data = 0x0 if not self.staged else self.staged  # TODO CHECK ME

        message = raft_definitions.raft_packet(sourceID=0,
                                               destinationID=1,
                                               srcIP=self.address,
                                               dstIP=voter_ip,
                                               logIndex=self.commitIndex,
                                               currentTerm=term,
                                               data=data,
                                               messageType=command)

        while self.status == STATUSES['candidate'] and self.term == term:

            logger.debug("{} sending vote request to: {}".format(self.address, voter_ip, self.term))
            reply = raft_definitions.send_raft_vote_request(voter_ip, message)

            if reply:
                # logger.debug("got reply: %s" % reply.sprintf(
                #     "IP:%IP.src%:%UDP.dport%;Raft voted:%Raft.voted%, term:%Raft.currentTerm%"
                # ))
                # logger.debug("my_term: {}, my_log: {}".format(self.term, self.log))

                choice = True if reply[Raft].voted == 0x1 else False

                logger.debug('Received Vote: {} from {}'.format(choice, reply[IP].src))

                if choice and self.status == STATUSES['candidate']:
                    self.increment_vote()

                elif not choice:
                    # they declined because either I'm out-of-date or not newest term
                    # update my term and terminate the vote_req
                    term = reply[Raft].currentTerm
                    if term > self.term:
                        self.term = term
                        self.status = STATUSES['follower']
                break

    def decide_vote(self, ip, term, commitIdx, staged):
        # new election
        # decline all non-up-to-date candidate's vote request as well
        # but update term all the time, not reset timeout during decision
        # also vote for someone that has our staged version or a more updated one
        logger.debug("{} Deciding vote for {}".format(self.address, ip))
        logger.debug("requester_logindex: {}; my_logindex: {}".format(commitIdx, self.commitIndex))
        print("Deciding vote for {}".format(ip))
        print("requester_logindex: {}; my_logindex: {}".format(commitIdx, self.commitIndex))

        if self.term < term and self.commitIndex <= commitIdx and (staged or (self.staged == staged)):  # FIXME CHECK ME
            self.reset_timeout()
            self.term = term
            return True, self.term
        else:
            return False, self.term

    def increment_vote(self):
        """voting for myself, and getting checking if I made it to become the leader"""
        self.voteCount += 1
        if self.voteCount >= self.majority:
            logger.debug("{} becomes the leader of term {}".format(self.address, self.term))
            print("{} becomes the leader of term {}".format(self.address, self.term))
            self.status = STATUSES['leader']
            self.leader = self.address
            logger.debug("status: {}".format(self.status))
            self.init_timeout()

            self.start_heartbeats()

    def start_heartbeats(self):
        print("Starting HEARTBEATS")
        logger.debug("Starting HEARTBEATS")
        if self.staged:
            # we have something staged at the beginning of our leadership
            # we consider it as a new payload just received and spread it around
            print('DEBUG staged: {}'.format(self.staged))
            self.new_request(self.staged)

        self.lock.acquire()

        for each in self.nodes:
            logger.debug("{} Created new send_heartbeat thread for {}".format(self.address, each))
            threading.Thread(target=self.send_heartbeat, args=(each,)).start()

        self.lock.release()

    def update_follower_log(self, follower):
        """Every 5 seconds, send to the follower a recover entries to check that the log is consistent"""

        # TODO instead of doing a periodically recovering, use an event-based mechanism
        #  ( for example a node that goes up informs the leader that he is
        #  up again and that his log may be not consistent)
        while True:
            index = 0

            try:
                for val in self.log:
                    message = raft_definitions.raft_packet(
                        sourceID=0x0,
                        destinationID=0x1,
                        dstIP=follower,
                        srcIP=self.address,
                        data=val,
                        currentTerm=self.term,
                        logIndex=index,
                        messageType=raft_definitions.COMMANDS['RecoverEntries']
                    )
                    raft_definitions.send_raft_heartbeat_with_log(follower, message)
                    index += 1

            except Exception as e:
                print('Error while sending recover messages: {}'.format(e))

            time.sleep(raft_definitions.RECOVER_TIME // 1000)

    def send_heartbeat(self, follower):
        # check if the new follower have same commit index, else we tell them to update to our log level

        #if len(self.log) > 0:
        threading.Thread(target=self.update_follower_log, args=(follower,)).start()

        command = raft_definitions.COMMANDS['HeartBeatRequest']
        message = raft_definitions.raft_packet(sourceID=0x0,
                                               destinationID=0x1,
                                               srcIP=self.address,
                                               dstIP=follower,
                                               currentTerm=self.term,
                                               messageType=command,
                                               logIndex=self.commitIndex,
                                               data=0x0)  # CHECK ME

        while self.status == STATUSES['leader']:
            # logger.debug("sending heartbeat request to: {}".format(follower))
            # print("sending heartbeat request to: {}".format(follower))

            start = time.time()

            reply = raft_definitions.send_raft_heartbeat(follower, message)

            if reply:
                term = reply[Raft].currentTerm

                self.heartbeat_reply_handler(term,
                                             follower)

            elif self.status != STATUSES['leader']:  # may be useless
                break

            delta = time.time() - start
            # keep the heartbeat constant even if the network speed is varying
            sleep_time = (raft_definitions.HEARTBEAT_TIME - delta) / 1000
            time.sleep(0 if sleep_time <= 0 else sleep_time)

        return

    def heartbeat_reply_handler(self, term, follower):
        # I thought I was leader, but a follower told me
        # that there is a new term, so i now step down
        if term > self.term:
            self.term = term
            self.status = STATUSES['follower']
            self.init_timeout()

        # print("HANDLED HEARTBEAT FROM {}".format(follower))

    def init_timeout(self):
        self.reset_timeout()
        # safety guarantee, timeout thread may expire after election
        if self.timeout_thread and self.timeout_thread.isAlive():
            return
        self.timeout_thread = threading.Thread(target=self.timeout_loop)
        self.timeout_thread.start()

    # the timeout function
    def timeout_loop(self):
        # only stop timeout thread when winning the election
        while self.status != STATUSES['leader']:
            delta = self.election_time - time.time()
            if delta < 0:
                self.start_election()
            else:
                time.sleep(delta)
        return

    def heartbeat_follower(self, msg):
        term = msg[Raft].currentTerm

        if self.term <= term:
            self.leader = msg[IP].src  # taking the ip of the leader
            # print("resetting timeout inside heartbeat_follower")
            self.reset_timeout()
            # in case I am not follower
            # or started an election and lost it
            if self.status == STATUSES['candidate']:
                self.status = STATUSES['follower']
            elif self.status == STATUSES['leader']:
                self.status = STATUSES['follower']
                self.init_timeout()
            # i have missed a few messages
            if self.term < term:
                self.term = term

            recover_command = raft_definitions.COMMANDS['RecoverEntries']
            append_entries_command = raft_definitions.COMMANDS['AppendEntries']

            if msg[Raft].messageType == append_entries_command and msg[Raft].data != 0x0:

                print("received append in follower ".format(msg[IP].src, msg[Raft].data))
                logger.debug("received an append entry from {}; value: {}".format(msg[IP].src, msg[Raft].data))
                self.staged = msg[Raft].data

            elif msg[Raft].messageType == recover_command:
                # recovering values from leader
                try:
                    if self.log[msg[Raft].logIndex] != msg[Raft].data:
                        self.staged = msg[Raft].data
                        self.insert(msg[Raft].logIndex)

                except IndexError as e:
                    self.staged = msg[Raft].data
                    self.insert(msg[Raft].logIndex)

            elif self.commitIndex <= msg[Raft].logIndex and msg[Raft].data != 0x0:
                if not self.staged:
                    self.staged = msg[Raft].data
                self.commit()

        return self.term, self.commitIndex

    def new_request(self, value):
        print("trying to insert {} inside the log".format(value))
        logger.debug("trying to insert {} inside the log".format(value))

        self.lock.acquire()
        self.staged = value

        waited = 0

        log_message = raft_definitions.raft_packet(
            sourceID=0x0,
            destinationID=0x1,
            data=value,
            logIndex=self.commitIndex,
            srcIP=self.address,
            dstIP=None,  # will be defined inside spread_update!
            currentTerm=self.term,
            messageType=raft_definitions.COMMANDS['AppendEntries']
        )

        log_confirmations = [False] * len(self.nodes)  # to see how many have approved the new value
        threading.Thread(target=self.spread_update,
                         args=(log_message, log_confirmations)).start()

        while sum(log_confirmations) + 1 < self.majority:
            waited += 0.005
            time.sleep(0.005)

            if waited > raft_definitions.MAX_LOG_WAIT / 1000:
                print("waited {} ms, update rejected:".format(raft_definitions.MAX_LOG_WAIT))
                logger.debug("waited {} ms, update rejected:".format(raft_definitions.MAX_LOG_WAIT))
                logger.debug("confirmations: {}".format(log_confirmations))

                self.lock.release()
                return False

        # reach this point only if a majority has replied and tell everyone to commit
        commit_message = raft_definitions.raft_packet(
            sourceID=0x0,
            destinationID=0x1,
            srcIP=self.address,
            dstIP=None,  # will be defined inside spread update!
            messageType=raft_definitions.COMMANDS['CommitValue'],
            data=value,
            logIndex=self.commitIndex,
            currentTerm=self.term
        )
        self.commit()
        threading.Thread(target=self.spread_update,
                         args=(commit_message, None, self.lock)).start()
        print("majority reached, replied to client, sending message to commit")
        return True

    # takes a message and an array of confirmations and spreads it to the followers
    # if it is a commit it releases the lock
    def spread_update(self, message, confirmations=None, lock=None):
        for i, node_ip in enumerate(self.nodes):
            message[IP].dst = node_ip  # setting the ip destination

            r = raft_definitions.send_raft_heartbeat_with_log(nodeIP=node_ip, message=message)

            if r and confirmations:
                logger.debug("reply for spread: {}".format(r[Raft].messageType))
                confirmations[i] = True

        if lock:
            lock.release()

    # consolidate the new value
    def commit(self):
        self.commitIndex += 1
        self.log.append(self.staged)
        print("committed new value: {}".format(self.staged))
        logger.debug("committed new value: {}".format(self.staged))
        print("log: {}".format(self.log))
        logger.debug("log: {}".format(self.log))
        # empty the staged so we can vote accordingly if there is a tie
        self.staged = None

    def insert(self, index=0):
        self.log.insert(index, self.staged)
        print("recovering log from leader. new value: {}".format(self.staged))
        logger.debug("recovering log from leader. new value: {}".format(self.staged))
        print("log: {}".format(self.log))
        self.commitIndex = len(self.log)
        self.staged = None

    def reset_timeout(self):
        self.election_time = time.time() + raft_definitions.raft_timeout()
