"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2025 Shane William Scott

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.

Author(s): Shane Scott (sscott@shanewilliamscott.com), Dmitriy Dubson (d.dubson@gmail.com)
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
