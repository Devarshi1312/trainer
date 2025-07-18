import frappe
import stripe
from frappe.auth import LoginManager
from frappe.utils.password import update_password
import hmac
import hashlib
import razorpay
from frappe.utils import now
import requests
from frappe import _

@frappe.whitelist(allow_guest=True)
def verify_captcha(token):
    """Verify Google reCAPTCHA token"""
    if not token:
        frappe.response["data"]={"success":False,"message":"Token is missing"}
        return
    secret_key = "6LdlancrAAAAAMlrgRQnIJU3z5lQgq6L-fM_KEd6"
    verify_url = "https://www.google.com/recaptcha/api/siteverify"

    resp = requests.post(verify_url, data={
        "secret": secret_key,
        "response": token
    }).json()

    if not resp.get("success"):
        frappe.response["data"] = {"success":False,"message":"Captcha validation failed"}
        return
    frappe.response["data"] = {"success": True}
    return

@frappe.whitelist(allow_guest=False)
def deduct_credits(user,trainer):
    wallet = frappe.get_doc("Credits", {"user": user})
    if wallet.credits >= 10:
        wallet.credits = wallet.credits - 10
        wallet.save()

        frappe.get_doc({
            "doctype": "Credit Transaction",
            "user": user,
            "transaction_type": "Usage",
            "credits": -10,
	    "reference_trainer":trainer
        }).insert()

        frappe.get_doc({
	    "doctype":"Unlocked Trainers",
	    "user":user,
	    "trainer":trainer
	}).insert()

        return {"success": True, "message": "success"}
    else:
        return {"success": False, "message": "Not enough credits. Please purchase more."}
    


stripe.api_key = frappe.conf.get("stripe_secret_key")

@frappe.whitelist()
def create_checkout_session(amount):
    user = frappe.session.user
    # amount = frappe.form_dict.get("amount")
    amount=int(amount)
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {
                            "name": "Credits Purchase",
                        },
                        "unit_amount": int(amount)*100//5,
                    },
                    "quantity": 1,
                },
            ],
            mode="payment",
            success_url=f"http://trainer.localhost:8000/payment_success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"http://trainer.localhost:8000/payment-failed",
        )
        return {"session_id": checkout_session.id, "redirect_url": checkout_session.url}
    except Exception as e:
        frappe.log_error(f"Stripe Error: {str(e)}", "Payment Error")
        frappe.throw("Unable to create payment session. Please try again.")

@frappe.whitelist(allow_guest=True)
def payment_success(session_id):
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.payment_status == "paid":
            user = frappe.session.user
            amount = session.amount_total // 50
            user_doc = frappe.get_all("Credits", filters={"user": user}, fields=["name","user", "credits"])

            if user_doc:
                credits_doc = frappe.get_doc("Credits", user_doc[0].get("name"))
                credits_doc.credits = credits_doc.credits + int(amount)
                credits_doc.save(ignore_permissions=True)  # Save changes

                transaction = frappe.get_doc({
                    "doctype": "Credit Transaction",  # Ensure this is the correct Doctype name
                    "user": user,
                    "transaction_type": "Purchase",
                    "credits": int(amount),  # Ensure amount is properly converted
                    "amount": session.amount_total / 100,  # Convert from paise to INR
                    "reference_trainer": None  # Explicitly setting to None
                })
                transaction.insert(ignore_permissions=True)

                frappe.db.commit()

                frappe.msgprint("Payment successful! Credits updated.")
                return {"status": "success", "message": "Credits added successfully"}
            else:
                return {"status": "failed", "message": "User not found in Credits Doctype"}

        else:
            return {"status": "failed", "message": "Payment not successful"}
    except Exception as e:
        frappe.log_error(f"Payment Success Error: {str(e)}", "Payment Error")
        return {"status": "failed", "message": "An error occurred."}



@frappe.whitelist(allow_guest=True)
def signup_User(email, first_name, password, last_name=None, roles=None):
    if not email or not first_name or not password:
        return {"status": "error", "message": "Email, First Name, and Password are required"}

    # Check if the user already exists
    existing_user = frappe.get_all("User", filters={"email": email})
    if existing_user:
        return {"status": "error", "message": "User with this email already exists"}
    if "user_role" in roles:
        role="user_role"
    elif "Trainer" in roles:
        role="Trainer"
    # Create a new user document
    user_doc = frappe.get_doc({
        "doctype": "User",
        "email": email,
        "first_name": first_name,
	    "last_name":last_name,
        "enabled": 1,
        "role_user": role,
        "new_password": password,
        "roles": [{"role": role} for role in roles],
    })

    try:
        # Insert the user document into the database
        user_doc.insert(ignore_permissions=True)

        update_password(user=email, pwd=password)

        # Send welcome email or other post-signup actions can be triggered here.
        #if user_doc:
        #	generate_otp(email)
#            subject="Welcome to our Platform",
#            message="Hello, {}! Welcome to our platform.".format(first_name)
#        )
        
        frappe.response["data"] = {"status": "success", "message": "User created successfully", "user_details": user_doc, "key_details":generate_key(email)}

    except Exception as e:
        frappe.log_error(f"Error creating user: {str(e)}", "Custom Signup Error")
        return {"status": "error", "message": "Error creating user: {}".format(str(e))}


@frappe.whitelist(allow_guest = True)
def customLogin(usr,pwd):
	login_manager = LoginManager()
	login_manager.authenticate(usr,pwd)
	login_manager.post_login()
#	print(frappe.response)
	if frappe.response['message'] == 'Logged In' or 'No App':
		user = login_manager.user
#		print(user)
		frappe.response['key_details'] = generate_key(user)
		frappe.response['user_details'] = get_user_details(user)
          
	else:
		return False
	
def generate_key(user):
	user_details = frappe.get_doc("User", user)
	api_secret = api_key = ''
	if not user_details.api_key and not user_details.api_secret:
		api_secret = frappe.generate_hash(length=15)
		api_key = frappe.generate_hash(length=15)
		user_details.api_key = api_key
		user_details.api_secret = api_secret
		user_details.save(ignore_permissions = True)
	else:
		api_secret = user_details.get_password('api_secret')
		api_key = user_details.get('api_key')
	return {"api_secret": api_secret,"api_key": api_key}

def get_user_details(user):
	print(user)
	user_details = frappe.get_all("User",filters={"name":user},fields=["name","first_name","last_name","email","role_user","last_login"])
	if user_details:
		trainer_id = frappe.db.get_value("Trainer", {"trainer": user}, "name")
		user_details[0]["name"] = trainer_id
		user_details[0]["is_first_login"] = not bool(trainer_id)
		return user_details[0]

@frappe.whitelist(allow_guest=True)
def get_all_trainers(user, page=1, page_size=10):
    """Fetch paginated trainers sorted by avg_review (desc)"""
    page = int(page)
    page_size = int(page_size)
    start = (page - 1) * page_size  # Calculate the offset

    # Ensure we fetch trainer names explicitly
    query = """
        SELECT 
            t.trainer,
            t.name,
            t.first_name,
            t.cover_image, 
            t.image, 
            t.avg_rating,
            t.city,
            t.charge,
	    t.experience,
	    t.expertise_in,
	    t.language,
	    t.profile_views,
            CASE 
                WHEN w.trainers IS NOT NULL THEN 1 
                ELSE 0 
            END AS is_wishlisted,
            CASE 
                WHEN u.trainer IS NOT NULL THEN 1 
                ELSE 0 
            END AS is_unlocked
        FROM tabTrainer t
        LEFT JOIN tabWishlist w ON w.trainers = t.trainer AND w.users = %(user)s
        LEFT JOIN `tabUnlocked Trainers` u ON u.trainer = t.trainer AND u.user = %(user)s
        ORDER BY t.avg_rating DESC
        LIMIT %(start)s, %(page_size)s
    """

    trainers = frappe.db.sql(
        query,
        {"user": user, "start": start, "page_size": page_size},
        as_dict=True
    )

    # Step 2: Fetch all expertise for the trainers
    trainer_ids = [trainer["trainer"] for trainer in trainers]

    for trainer in trainers:
        if frappe.db.exists("Trainer", trainer["name"]):
            result = frappe.get_doc("Trainer", trainer["name"])
            # Extract expertise as a list of strings
            trainer["expertise_in"] = result.expertise_in
        else:
            trainer["expertise_in"] = []

    # Get wishlist trainers for the current user
    wishlist_trainers = frappe.db.get_all(
        "Wishlist",
        filters={"users": user},
        fields=["*"]
    )
    wishlist_trainer_ids = {entry["trainers"] for entry in wishlist_trainers}

    # Get unlocked trainers for the current user
    unlocked_trainers = frappe.db.get_all(
        "Unlocked Trainers",
        filters={"user": user},
        fields=["*"]
    )
    unlocked_trainer_ids = {entry["trainer"] for entry in unlocked_trainers}

    # Mark trainers as wishlisted and unlocked
    for trainer in trainers:
        trainer_id = trainer["name"]  # Use 'name' instead of 'trainer'
        trainer["is_wishlisted"] = 1 if trainer_id in wishlist_trainer_ids else 0
        trainer["is_unlocked"] = 1 if trainer_id in unlocked_trainer_ids else 0

    for trainer in unlocked_trainers:
        trainer_id = trainer["trainer"]
        trainer["is_wishlisted"] = 1 if trainer_id in wishlist_trainer_ids else 0

    unlocked=[]
    for trainer in trainers:
         if trainer["is_unlocked"]:
              unlocked.append(trainer)

    locked=[]
    for trainer in trainers:
         if trainer["is_unlocked"] == 0:
              locked.append(trainer)

    wishlist=[]
    for trainer in trainers:
         if trainer["is_wishlisted"]:
              wishlist.append(trainer)

    # Get total count for pagination
    total_count = frappe.db.count("Trainer")
    for trainer in trainers:
        reviews = frappe.get_all(
            "Ratings_Reviews",
            filters={"trainers": trainer.name},
            fields=["users", "user_name", "review", "rating","trainers"]
        )

        # Calculate average rating
        avg_rating = 0.0
        if reviews:
            total = sum([r.rating for r in reviews])
            avg_rating = round(total / len(reviews), 1)
        trainer["avg_rating"] = avg_rating
    return {
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "All_trainers": trainers,
      }



@frappe.whitelist()
def search_trainers(search_text=None, location=None, expertise=None, sort_by="rating", order="desc", page=1, page_size=10):
    """
    Search trainers based on full_name, expertise, and location.
    Filters: location, expertise.
    Sorting: price (high to low, low to high), rating (high to low, low to high).
    """
    page = int(page)
    page_size = int(page_size)
    start = (page - 1) * page_size

    # Base SQL query
    query = """
        SELECT 
            t.trainer, t.full_name, t.location, t.charge, t.avg_rating, t.cover_image, t.image,
            GROUP_CONCAT(DISTINCT e.expertise ORDER BY e.expertise SEPARATOR ', ') AS expertise
        FROM tabTrainer t
        LEFT JOIN tabExpertise e ON e.trainer = t.name
        WHERE 1=1
    """
    
    filters = {}
    
    # Apply location filter
    if location:
        query += " AND t.location = %(location)s"
        filters["location"] = location

    # Apply search query (searching in full_name and expertise)
    if search_text:
        query += " AND t.full_name LIKE %(search_text)s"
        filters["search_text"] = f"%{search_text}%"

    if expertise:
        query += " AND e.expertise LIKE %(expertise)s"
        filters["expertise_in"] = f"%{expertise}%"

    # Sorting options
    sort_column = "t.avg_rating" if sort_by == "rating" else "t.charge"
    sort_order = "DESC" if order == "desc" else "ASC"
    query += f" ORDER BY {sort_column} {sort_order}"

    # Pagination
    query += " LIMIT %(page_size)s OFFSET %(start)s"
    filters["page_size"] = page_size
    filters["start"] = start

    # Execute query
    trainers = frappe.db.sql(query, filters, as_dict=True)

    # Get total count for pagination
    count_query = """
        SELECT COUNT(DISTINCT t.trainer) AS total
        FROM tabTrainer t
        LEFT JOIN tabExpertise_in e ON e.trainer = t.trainer
        WHERE 1=1
    """
    if location:
        count_query += " AND t.location = %(location)s"
    if search_text:
        count_query += " AND t.full_name LIKE %(search_text)s"
    if expertise:
        count_query += " AND e.expertise LIKE %(expertise)s"

    total_count = frappe.db.sql(count_query, filters, as_dict=True)[0]["total"]

    return {
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "trainers": trainers
    }


@frappe.whitelist(allow_guest=True)
def create_order(amount):
    try:
        user = frappe.session.user  # Or pass it explicitly as an argument

        amount = int(amount)
        if amount < 1:
            frappe.throw(_("Amount must be greater than 0"))

        key_id = frappe.conf.get("razorpay_key_id")
        key_secret = frappe.conf.get("razorpay_key_secret")
        client = razorpay.Client(auth=(key_id, key_secret))

        order = client.order.create({
            "amount": amount * 100,
            "currency": "INR",
            "receipt": f"receipt_{frappe.generate_hash(length=10)}",
            "payment_capture": 1,
            "notes": {
                "created_by": "frappe_backend",
                "user": user,
                "created_at": now()
            }
        })

        return {
            "status": "success",
            "order_id": order.get("id"),
            "amount": order.get("amount"),
            "currency": order.get("currency"),
            "receipt": order.get("receipt")
        }

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Razorpay Order Creation Failed")
        return {"status": "error", "message": str(e)}

def get_razorpay_client():
    import razorpay
    key_id = frappe.conf.get("razorpay_key_id")
    key_secret = frappe.conf.get("razorpay_key_secret")
    if not key_id or not key_secret:
        frappe.throw("Razorpay credentials missing")
    return razorpay.Client(auth=(key_id, key_secret))

@frappe.whitelist(allow_guest=True)
def verify_payment_and_update_credits(razorpay_payment_id, razorpay_order_id, razorpay_signature):
    """
    Verifies the Razorpay payment signature and updates Credits and Credit Transaction DocTypes.
    """
    try:
        # Step 1: Get Razorpay secret
        key_secret = frappe.conf.get("razorpay_key_secret")
        if not key_secret:
            frappe.throw(_("Razorpay key_secret not found in site_config"))

        # Step 2: Verify the signature
        generated_signature = hmac.new(
            key_secret.encode(),
            f"{razorpay_order_id}|{razorpay_payment_id}".encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(generated_signature, razorpay_signature):
            return {"status": "failed", "message": "Invalid payment signature"}

        # Step 3: Fetch order details using Razorpay API (optional, but helpful)
        client = get_razorpay_client()
        payment = client.payment.fetch(razorpay_payment_id)

        if payment['status'] != "captured":
            return {"status": "failed", "message": "Payment not captured yet"}

        # Step 4: Update Credits and Transaction
        user = frappe.session.user
        amount_in_paise = int(payment["amount"])
        amount_in_inr = amount_in_paise / 100
        credits_to_add = amount_in_inr // 5  # You can change conversion logic here

        # Get or create Credits Doc
        user_doc = frappe.get_all("Credits", filters={"user": user}, fields=["name", "credits"])

        if user_doc:
            credits_doc = frappe.get_doc("Credits", user_doc[0].name)
            credits_doc.credits += credits_to_add
            credits_doc.save(ignore_permissions=True)
        else:
            # Create new Credits Doc if not found
            credits_doc = frappe.get_doc({
                "doctype": "Credits",
                "user": user,
                "credits": credits_to_add
            }).insert(ignore_permissions=True)

        # Create Credit Transaction Doc
        transaction = frappe.get_doc({
            "doctype": "Credit Transaction",
            "user": user,
            "transaction_type": "Purchase",
            "credits": credits_to_add,
            "amount": amount_in_inr,
            "reference_trainer": None
        }).insert(ignore_permissions=True)

        frappe.db.commit()

        return {"status": "success", "message": "Credits updated successfully"}

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Razorpay Payment Verification Failed")
        return {"status": "failed", "message": "An error occurred during payment verification.","error":e}

@frappe.whitelist(allow_guest=True)
def global_trainer_search(search_text=None,category=None, city_filter=None, page=1, page_size=10):
    params = {}
    where_conditions = []

    # Pagination calculations
    try:
        page = int(page)
        page_size = int(page_size)
    except ValueError:
        page = 1
        page_size = 10

    offset = (page - 1) * page_size

    if search_text:
        params["search"] = f"%{search_text.lower()}%"
        where_conditions.append("""
            (
                LOWER(t.name) LIKE %(search)s OR
                LOWER(t.full_name) LIKE %(search)s OR
                LOWER(t.avg_rating) LIKE %(search)s OR
                LOWER(t.expertise_in) LIKE %(search)s OR
                LOWER(t.experience) LIKE %(search)s OR
                LOWER(t.city) LIKE %(search)s OR
                LOWER(t.charge) LIKE %(search)s OR
                LOWER(t.profile_views) LIKE %(search)s OR
                LOWER(t.status) LIKE %(search)s OR
                LOWER(t.language) LIKE %(search)s
            )
        """)

    if city_filter:
        params["city"] = city_filter
        where_conditions.append("LOWER(t.city) = LOWER(%(city)s)")
    if category:
        params["category"] = f"%{category}%"
        where_conditions.append("LOWER(t.expertise_in) LIKE LOWER(%(category)s)")

    where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"

    query = f"""
        SELECT DISTINCT t.name,t.first_name, t.full_name, t.avg_rating, t.expertise_in, t.experience,
               t.city, t.charge, t.profile_views, t.status, t.image, t.language
        FROM tabTrainer t
        WHERE {where_clause}
        ORDER BY t.full_name
        LIMIT {page_size} OFFSET {offset}
    """

    # Optionally add total count for frontend pagination UI
    trainers = frappe.db.sql(query, params, as_dict=True)

    # Optional: get total count for pagination
    count_query = f"""SELECT COUNT(*) as total FROM tabTrainer t WHERE {where_clause}"""
    total_count = frappe.db.sql(count_query, params, as_dict=True)[0]["total"]

    # Wishlist logic: Get all trainer names in user's wishlist
    user = frappe.session.user
    wishlisted = set()
    if user and user != "Guest":
        wishlist_entries = frappe.get_all(
            "Wishlist",
            filters={"users": user},
            fields=["trainers"]
        )
        wishlisted = {entry.trainers for entry in wishlist_entries}

    # Append is_wishlisted flag
    for trainer in trainers:
        trainer["is_wishlisted"] = 1 if trainer["name"] in wishlisted else 0
    # Get unlocked trainers for the current user
    unlocked_trainers = frappe.db.get_all(
        "Unlocked Trainers",
        filters={"user": user},
        fields=["*"]
    )
    unlocked_trainer_ids = {entry["trainer"] for entry in unlocked_trainers}

    # Mark trainers as wishlisted and unlocked
    for trainer in trainers:
        trainer_id = trainer["name"]  # Use 'name' instead of 'trainer'
        trainer["is_unlocked"] = 1 if trainer_id in unlocked_trainer_ids else 0

    for trainer in trainers:
        reviews = frappe.get_all(
            "Ratings_Reviews",
            filters={"trainers": trainer.name},
            fields=["users", "user_name", "review", "rating","trainers"]
        )

        # Calculate average rating
        avg_rating = 0.0
        if reviews:
            total = sum([r.rating for r in reviews])
            avg_rating = round(total / len(reviews), 1)
        trainer["avg_rating"] = avg_rating
    frappe.response["data"] = {
        "results": trainers,
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": (total_count + page_size - 1) // page_size
    }

@frappe.whitelist(allow_guest=True)
def company_trainers(user, page=1, page_size=8):
    """Fetch paginated trainers sorted by avg_review (desc)"""
    page = int(page)
    page_size = int(page_size)
    start = (page - 1) * page_size  # Calculate the offset

    # Ensure we fetch trainer names explicitly
    query = """
        SELECT
            t.trainer,
            t.full_name,
            t.name,
            t.first_name,
            t.last_name,
            t.cover_image,
            t.image,
            t.avg_rating,
            t.city,
            t.charge,
	    t.expertise_in,
	    t.experience,
	    t.language,
	    t.profile_views,
            CASE
                WHEN w.trainers IS NOT NULL THEN 1
                ELSE 0
            END AS is_wishlisted,
            CASE
                WHEN u.trainer IS NOT NULL THEN 1
                ELSE 0
            END AS is_unlocked
        FROM tabTrainer t
        LEFT JOIN tabWishlist w ON w.trainers = t.trainer AND w.users = %(user)s
        LEFT JOIN `tabUnlocked Trainers` u ON u.trainer = t.trainer AND u.user = %(user)s
        ORDER BY t.avg_rating DESC
    """

    trainers = frappe.db.sql(
        query,
        {"user": user, "start": start, "page_size": page_size},
        as_dict=True
    )

    # Step 2: Fetch all expertise for the trainers
    trainer_ids = [trainer["trainer"] for trainer in trainers]

    for trainer in trainers:
        if frappe.db.exists("Trainer", trainer["name"]):
            result = frappe.get_doc("Trainer", trainer["name"])
            # Extract expertise as a list of strings
            trainer["expertise_in"] = result.expertise_in
        else:
            trainer["expertise_in"] = []

    # Get wishlist trainers for the current user
    wishlist_trainers = frappe.db.get_all(
        "Wishlist",
        filters={"users": user},
        fields=["*"]
    )
    wishlist_trainer_ids = {entry["trainers"] for entry in wishlist_trainers}

    # Get unlocked trainers for the current user
    unlocked_trainers = frappe.db.get_all(
        "Unlocked Trainers",
        filters={"user": user},
        fields=["*"]
    )
    unlocked_trainer_ids = {entry["trainer"] for entry in unlocked_trainers}

    # Mark trainers as wishlisted and unlocked
    for trainer in trainers:
        trainer_id = trainer["name"]  # Use 'name' instead of 'trainer'
        trainer["is_wishlisted"] = 1 if trainer_id in wishlist_trainer_ids else 0
        trainer["is_unlocked"] = 1 if trainer_id in unlocked_trainer_ids else 0

    for trainer in unlocked_trainers:
        trainer_id = trainer["trainer"]
        trainer["is_wishlisted"] = 1 if trainer_id in wishlist_trainer_ids else 0

    unlocked=[]
    for trainer in trainers:
         if trainer["is_unlocked"]:
              unlocked.append(trainer)

    locked=[]
    for trainer in trainers:
         if trainer["is_unlocked"] == 0:
              locked.append(trainer)

    wishlist=[]
    for trainer in trainers:
         if trainer["is_wishlisted"]:
              wishlist.append(trainer)

    # Get total count for pagination
    total_count = frappe.db.count("Trainer")

    return {
        "unlocked_trainers": unlocked,
        "wishlist_trainers": wishlist
    }

@frappe.whitelist(allow_guest=True)
def get_trainer(trainer_id):
    try:
        trainer_doc = frappe.get_doc("Trainer", trainer_id)
    except frappe.DoesNotExistError:
        frappe.response["http_status_code"] = 404
        frappe.response["message"] = _("Trainer not found")
        return
    unlocks = frappe.get_all(
	"Unlocked Trainers",
	filters={"trainer":trainer_id}
    )
    # Fetch reviews
    reviews = frappe.get_all(
        "Ratings_Reviews",
        filters={"trainers": trainer_id},
        fields=["users", "user_name", "review", "rating","trainers"]
    )

    # Calculate average rating
    avg_rating = 0.0
    if reviews:
        total = sum([r.rating for r in reviews])
        avg_rating = round(total / len(reviews), 1)

    trainer_data = {
        "name": trainer_doc.name,
        "trainer": trainer_doc.trainer,
        "full_name": trainer_doc.first_name,
        "bio_line": trainer_doc.bio_line,
        "experience": trainer_doc.experience,
        "city": trainer_doc.city,
        "expertise_in": trainer_doc.expertise_in,
        "language": trainer_doc.language,
        "charge": trainer_doc.charge,
        "profile_views": trainer_doc.profile_views,
        "avg_rating": avg_rating,
	"total_reviews":len(reviews),
        "image": trainer_doc.image,
	"total_unlocks":len(unlocks),
        "training_approach": trainer_doc.training_approach,
        "education": [
            {
                "course": e.course,
                "institution": e.institution,
                "year": e.year
            } for e in trainer_doc.education
        ],
        "certificates": [
            {
                "certificate_name": c.certificate_name,
                "certificate_url": c.certificate_url,
                "issued_by": c.issued_by,
                "issued_date": c.issued_date
            } for c in trainer_doc.certificates
        ],
        "testimonials": [
            {
                "client_name": t.client_name,
                "testimonials": t.testimonials,
                "company": t.company
            } for t in trainer_doc.testimonials
        ],
        "client_worked": [
            {
                "company": i.company
            } for i in trainer_doc.client_worked
        ],
        "reviews": [
            {
                "review": r.review,
                "rating": r.rating,
                "user_name": r.user_name,
                "creation": r.created_on
            } for r in reviews
        ],
        "workshop": trainer_doc.workshop,
        "dob": trainer_doc.dob,
        "phone": trainer_doc.phone,
        "facebook": trainer_doc.facebook,
        "instagram": trainer_doc.instagram,
        "twitter": trainer_doc.twitter,
        "linkedin": trainer_doc.linkedin,
        "personal_website": trainer_doc.personal_website,
        "is_unlocked": 1
    }
    trainer = frappe.get_doc("Trainer", trainer_id)
    trainer.profile_views = int(trainer.profile_views or 0) + 1
    trainer.save(ignore_permissions=True)
    frappe.db.commit()
    #frappe.response["message"] = "Trainer profile fetched successfully"
    frappe.response["data"] = trainer_data


@frappe.whitelist(allow_guest=True)
def get_trainer_profile(trainer_id):
    try:
        trainer_doc = frappe.get_doc("Trainer", trainer_id)
    except frappe.DoesNotExistError:
        frappe.response["http_status_code"] = 404
        frappe.response["message"] = _("Trainer not found")
        return

    # Check if trainer is unlocked for the current user
    is_unlocked = False
    user = frappe.session.user
    if user and user != "Guest":
        is_unlocked = frappe.db.exists("Unlocked Trainers", {
            "user": user,
            "trainer": trainer_id
        })
    unlocks = frappe.get_all(
        "Unlocked Trainers",
        filters={"trainer":trainer_id}
    )

    # Fetch reviews
    reviews = frappe.get_all(
        "Ratings_Reviews",
        filters={"trainers": trainer_id},
        fields=["users", "user_name", "review", "rating","trainers"]
    )

    avg_rating = 0.0
    if reviews:
        total = sum([r.rating for r in reviews])
        avg_rating = round(total / len(reviews), 1)

    trainer_data = {
        "name": trainer_doc.name,
        "trainer": trainer_doc.trainer,
        "full_name": trainer_doc.first_name,
        "bio_line": trainer_doc.bio_line,
        "experience": trainer_doc.experience,
        "city": trainer_doc.city,
        "expertise_in": trainer_doc.expertise_in,
        "language": trainer_doc.language,
        "charge": trainer_doc.charge,
        "profile_views": trainer_doc.profile_views,
        "avg_rating": avg_rating,
        "image": trainer_doc.image,
	"total_unlocks":len(unlocks),
	"total_reviews":len(reviews),
        "training_approach": trainer_doc.training_approach,
        "education": [
            {
                "course": e.course,
                "institution": e.institution,
                "year": e.year
            } for e in trainer_doc.education
        ],
        "certificates": [
            {
                "certificate_name": c.certificate_name,
                "certificate_url": c.certificate_url,
                "issued_by": c.issued_by,
                "issued_date": c.issued_date
            } for c in trainer_doc.certificates
        ],
        "testimonials": [
            {
                "client_name": t.client_name,
                "testimonials": t.testimonials,
                "company": t.company
            } for t in trainer_doc.testimonials
        ],
        "client_worked": [
            {
                "company": i.company
            } for i in trainer_doc.client_worked
        ],
        "reviews": reviews,
        "workshop": trainer_doc.workshop,
        "dob": trainer_doc.dob,
        "is_unlocked": 1 if is_unlocked else 0
    }

    if is_unlocked:
        trainer_data.update({
	    "full_name":trainer_doc.full_name,
            "phone": trainer_doc.phone,
            "facebook": trainer_doc.facebook,
            "instagram": trainer_doc.instagram,
            "twitter": trainer_doc.twitter,
            "linkedin": trainer_doc.linkedin,
            "personal_website": trainer_doc.personal_website,
        })
    trainer = frappe.get_doc("Trainer", trainer_id)
    trainer.profile_views = int(trainer.profile_views or 0) + 1
    trainer.save(ignore_permissions=True)
    frappe.db.commit()
    #frappe.response["message"] = "Trainer public profile fetched"
    frappe.response["data"] = trainer_data
