#!/usr/bin/python

__author__ =  'yunshu(wustyunshu@hotmail.com)'
__version__=  '0.2'

class Session:
    def __init__(self, SessionHT):
        self.startTime = SessionHT.get('startTime', '')
        self.finish_time = SessionHT.get('finish_time', '')
        self.nmapVersion = SessionHT.get('nmapVersion', '')
        self.scanArgs = SessionHT.get('scanArgs', '')
        self.totalHosts = SessionHT.get('totalHosts', '')
        self.upHosts = SessionHT.get('upHosts', '')
        self.downHosts = SessionHT.get('downHosts', '')
        # List of progress snapshots, each is a dict with keys: percent, remaining, elapsed, task, etc.
        self.progress_data = []

    def add_progress(self, progress_dict):
        """Add a progress snapshot (dict) to the session."""
        self.progress_data.append(progress_dict)

    def get_latest_progress(self):
        """Return the most recent progress snapshot, or None if none exist."""
        if self.progress_data:
            return self.progress_data[-1]
        return None
