# Copyright (c) 2025, Devarshi and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class Wishlist(Document):
    def validate(self):
        if frappe.db.exists("Wishlist", {"users": self.users, "trainers": self.trainers, "name": ["!=", self.name]}):
            frappe.throw(f"Combination of {self.users} and {self.trainers} already exists.")

