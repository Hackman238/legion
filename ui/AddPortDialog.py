#!/usr/bin/env python

"""
LEGION (https://shanewilliamscott.com)
AddPortDialog - Dialog for manually adding a port to a host.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt

class AddPortDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupLayout()

    def setupLayout(self):
        self.setModal(True)
        self.setWindowTitle('Add Port to Host')
        self.resize(350, 200)

        layout = QVBoxLayout()

        # Port Number
        port_layout = QHBoxLayout()
        port_label = QLabel('Port Number:')
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText('e.g. 22')
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)
        layout.addLayout(port_layout)

        # State
        state_layout = QHBoxLayout()
        state_label = QLabel('State:')
        self.state_input = QComboBox()
        self.state_input.addItems(['open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered'])
        state_layout.addWidget(state_label)
        state_layout.addWidget(self.state_input)
        layout.addLayout(state_layout)

        # Protocol
        proto_layout = QHBoxLayout()
        proto_label = QLabel('Protocol:')
        self.proto_input = QComboBox()
        self.proto_input.addItems(['tcp', 'udp', 'sctp', 'icmp'])
        proto_layout.addWidget(proto_label)
        proto_layout.addWidget(self.proto_input)
        layout.addLayout(proto_layout)

        # Spacer
        layout.addItem(QSpacerItem(20, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Buttons
        button_layout = QHBoxLayout()
        self.submit_btn = QPushButton('Submit')
        self.cancel_btn = QPushButton('Cancel')
        button_layout.addWidget(self.submit_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        # Connect buttons
        self.cancel_btn.clicked.connect(self.reject)
        self.submit_btn.clicked.connect(self.accept)

    def get_port_data(self):
        return {
            'port': self.port_input.text().strip(),
            'state': self.state_input.currentText(),
            'protocol': self.proto_input.currentText()
        }
