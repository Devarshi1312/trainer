import frappe
import stripe
stripe.api_key = frappe.conf.get("stripe_secret_key")
def get_context(context):
    session_id = frappe.form_dict.get("session_id")
    context.payment_details = None

    if not session_id:
        context.error = "Invalid session ID."
        return context

    try:
        session = stripe.checkout.Session.retrieve(session_id)

        if session.payment_status == "paid":
            user = frappe.session.user
            amount = session.amount_total // 10

            user_doc = frappe.get_all("Credits", filters={"user": user}, fields=["name", "credits"])

            if user_doc:
                credits_doc = frappe.get_doc("Credits", user_doc[0].get("name"))
                credits_doc.credits = credits_doc.credits + int(amount)
                credits_doc.save(ignore_permissions=True)

                transaction = frappe.get_doc({
                    "doctype": "Credit Transaction",  
                    "user": user,
                    "transaction_type": "Purchase",
                    "credits": int(amount)//100,
                    "amount": session.amount_total / 100,
                    "reference_trainer": None
                })
                transaction.insert(ignore_permissions=True)

                frappe.db.commit()
                context.payment_details = {
                    "transaction_id": session.payment_intent,
                    "amount_paid": session.amount_total,
                    "currency": session.currency.upper(),
                    "credits_added": int(amount),
                    "payment_method": session.payment_method_types[0] if session.payment_method_types else "N/A",
                    "customer_email": session.customer_details.email if session.customer_details else "N/A"
                }
            else:
                context.error = "User not found in Credits Doctype"
        else:
            context.error = "Payment not successful"
    except Exception as e:
        frappe.log_error(f"Payment Success Error: {str(e)}", "Payment Error")
        context.error = "An error occurred while fetching payment details."

    return context
