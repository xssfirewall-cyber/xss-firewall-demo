"""
Self-Supervised Online Adapter
==============================
Sits in front of the MAFS ensemble at serving time and turns every
prediction into a pseudo-supervised signal — no human-labelled feedback
required.

Mechanism (per request):
  1) Read the ensemble's per-agent active votes and final classifier score.
  2) Compute the binary entropy of the vote ratio.
  3) Classify the event:
       - consensus_benign    : low entropy + low score   -> pseudo-label 0
       - consensus_xss       : low entropy + high score  -> pseudo-label 1
       - uncertain (drift)   : high entropy or mid score -> no label, drift++
  4) Append the record to a sliding-window replay buffer.
  5) When drift_counter crosses DRIFT_THRESHOLD, emit a micro-update event
     and decay exploration epsilon on the lowest-agreement agents.

Nothing here writes weights to the on-disk .keras files — those are the
training-time artefacts. The adapter maintains its own in-memory state
(epsilons, buffer, drift counter, micro-update log) that the dashboard
visualises live.
"""

import math
import time
import logging
from collections import deque
from typing import Dict, Optional


logger = logging.getLogger('online-adapter')


class OnlineAdapter:
    DRIFT_THRESHOLD = 5
    BUFFER_SIZE = 200
    EPSILON_START = 0.10
    EPSILON_MIN = 0.01
    EPSILON_DECAY = 0.85

    def __init__(self, num_agents: int = 10):
        self.num_agents = num_agents
        self.buffer: deque = deque(maxlen=self.BUFFER_SIZE)
        self.micro_updates: list = []
        self.drift_counter = 0
        self.epsilons = [self.EPSILON_START] * num_agents
        self.stats = {
            'pseudo_labeled':   0,
            'uncertain':        0,
            'consensus_xss':    0,
            'consensus_benign': 0,
            'total_observed':   0,
        }
        self._agent_disagreement_score = [0.0] * num_agents
        logger.info("OnlineAdapter ready (drift_threshold=%d)", self.DRIFT_THRESHOLD)

    def _binary_entropy(self, p: float) -> float:
        if p <= 0.0 or p >= 1.0:
            return 0.0
        return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))

    def _classify_event(self, votes: int, score: float):
        vote_p = votes / self.num_agents
        entropy = self._binary_entropy(vote_p)

        if entropy < 0.5 and score < 0.30:
            return 'consensus_benign', 0, 1.0 - score, entropy
        if entropy < 0.5 and score > 0.70:
            return 'consensus_xss', 1, score, entropy
        return 'uncertain', None, 0.0, entropy

    def _track_agent_disagreement(self, agents_decisions: list, pseudo_label: Optional[int]) -> None:
        if pseudo_label is None:
            return
        for d in agents_decisions:
            agent_vote = 1 if d.get('activation_score', 0) > 0 else 0
            if agent_vote != pseudo_label:
                self._agent_disagreement_score[d['agent_id']] += 1.0
            else:
                self._agent_disagreement_score[d['agent_id']] *= 0.95

    def observe(self, text: str, prediction: Dict) -> Dict:
        self.stats['total_observed'] += 1
        votes = int(prediction.get('active_votes', 0))
        score = float(prediction.get('score', 0.0))
        agents = prediction.get('agents', [])

        flag, pseudo_label, confidence, entropy = self._classify_event(votes, score)

        if flag == 'consensus_benign':
            self.stats['consensus_benign'] += 1
            self.stats['pseudo_labeled'] += 1
        elif flag == 'consensus_xss':
            self.stats['consensus_xss'] += 1
            self.stats['pseudo_labeled'] += 1
        else:
            self.stats['uncertain'] += 1
            self.drift_counter += 1

        self._track_agent_disagreement(agents, pseudo_label)

        record = {
            'text':         text[:80] if text else '',
            'score':        round(score, 4),
            'votes':        votes,
            'entropy':      round(entropy, 4),
            'flag':         flag,
            'pseudo_label': pseudo_label,
            'confidence':   round(confidence, 4),
            'ts':           time.time(),
        }
        self.buffer.append(record)

        triggered = False
        if self.drift_counter >= self.DRIFT_THRESHOLD:
            self._trigger_micro_update()
            triggered = True

        return {
            **record,
            'micro_update_triggered': triggered,
            'drift_counter':          self.drift_counter,
        }

    def _trigger_micro_update(self) -> None:
        ranked = sorted(
            range(self.num_agents),
            key=lambda i: self._agent_disagreement_score[i],
            reverse=True,
        )
        targets = ranked[:3]

        for i in targets:
            self.epsilons[i] = max(self.EPSILON_MIN, self.epsilons[i] * self.EPSILON_DECAY)
            self._agent_disagreement_score[i] *= 0.5

        update_event = {
            'ts':                time.time(),
            'reason':            'drift_threshold_reached',
            'drift_count':       self.drift_counter,
            'agents_updated':    targets,
            'new_epsilons':      [round(self.epsilons[i], 4) for i in targets],
            'buffer_size_at_event': len(self.buffer),
        }
        self.micro_updates.append(update_event)
        if len(self.micro_updates) > 50:
            self.micro_updates.pop(0)

        self.drift_counter = 0
        logger.info("Micro-update triggered: targets=%s eps=%s", targets, update_event['new_epsilons'])

    def state(self) -> Dict:
        return {
            'num_agents':       self.num_agents,
            'buffer_size':      len(self.buffer),
            'buffer_max':       self.BUFFER_SIZE,
            'drift_counter':    self.drift_counter,
            'drift_threshold':  self.DRIFT_THRESHOLD,
            'stats':            dict(self.stats),
            'epsilons':         [round(e, 4) for e in self.epsilons],
            'disagreement':     [round(d, 4) for d in self._agent_disagreement_score],
            'micro_updates':    self.micro_updates[-15:],
            'recent_events':    list(self.buffer)[-20:],
        }
