from datetime import timezone
from flask import current_app, flash, redirect, render_template, request, session, url_for
import os

from datetime import datetime, timedelta
import hashlib

merchant_id = os.getenv('PAYFAST_MERCHANT_ID')
merchant_key = os.getenv('PAYFAST_MERCHANT_KEY')


def payment_op():
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))

    plan = request.args.get('plan', 'monthly')
    amount = request.args.get('amount', '149.00')
    recurring = request.args.get('recurring', 'false') == 'true'

    if plan == 'annual':
        item_name = 'Premium Plan - Annual Subscription'
        recurring_amount = '1548.00'
        frequency = 6  # 6 = yearly in PayFast
    else:
        item_name = 'Premium Plan - Monthly Subscription'
        recurring_amount = '149.00'
        frequency = 3  # 3 = monthly in PayFast

    # Generate unique merchant reference for better tracking
    merchant_ref = f"{user.get('email', '')}-{plan}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    
    payfast_data = {
            'merchant_id': merchant_id,
        'merchant_key': merchant_key,
        'amount': amount,
        'item_name': item_name,
        'name_first': user.get('name', ''),
        'email_address': user.get('email', ''),
        'return_url': url_for('pay_success', _external=True),
        'cancel_url': url_for('pay_cancel', _external=True),
        'notify_url': url_for('pay_notify', _external=True),
        'custom_str1': user.get('email', ''),
        'custom_str2': plan,
        'custom_str3': merchant_ref,
        'm_payment_id': merchant_ref
    }

    if recurring:
        billing_date = (datetime.now(timezone.utc) + timedelta(days=1)).strftime('%Y-%m-%d')
        payfast_data.update({
            'subscription_type': 1,
            'billing_date': billing_date,
            'recurring_amount': recurring_amount,
            'frequency': frequency,
            'cycles': 0
        })
        
        current_app.logger.info(f"Creating recurring subscription for {user.get('email', '')}: {payfast_data}")
        print(f"Recurring subscription data: {payfast_data}")  # Terminal log

    return render_template('payfast_form.html', payfast=payfast_data, recurring=recurring)

def payment_successful(users_collection):
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))
    
    # Get plan from query parameters (in case it was passed back from PayFast)
    plan = request.args.get('plan', 'monthly')
    
    # Calculate subscription end date
    if plan == 'annual':
        subscription_end = datetime.now(timezone.utc) + timedelta(days=365)
        plan_display = "annual"
    else:
        subscription_end = datetime.now(timezone.utc) + timedelta(days=30)
        plan_display = "monthly"
    
    # Mark user as premium in DB with subscription details
    users_collection.update_one(
        {'email': user['email']}, 
        {'$set': {
            'premium': True,
            'subscription_plan': plan,
            'subscription_start': datetime.now(timezone.utc),
            'subscription_end': subscription_end
        }}
    )
    
    # Update session
    session['user']['premium'] = True
    session['user']['subscription_plan'] = plan
    
    # Show appropriate success message
    if plan == 'annual':
        flash('Payment successful! You are now a premium user with an annual subscription.', 'success')
    else:
        flash('Payment successful! You are now a premium user with a monthly subscription.', 'success')
    
    return redirect(url_for('chat'))


def payment_notification(users_collection, PAYFAST_SANDBOX, PAYFAST_PASSPHRASE):
    # Get the raw POST data from PayFast
    raw_body = request.get_data(as_text=True)
    received_signature = request.form.get('signature')

    print("--- PayFast ITN Received ---")
    current_app.logger.info("--- PayFast ITN Received ---")
    print(f"Raw ITN Body: {raw_body}")
    current_app.logger.info(f"Raw ITN Body: {raw_body}")
    print(f"Received Signature: {received_signature}")
    current_app.logger.info(f"Received Signature: {received_signature}")

    # Find the start of the signature in the raw body
    signature_part = "&signature="
    signature_index = raw_body.rfind(signature_part)
    
    # The string to hash is everything BEFORE the signature part
    payload_to_hash = raw_body[:signature_index]
    
    print(f"String to Hash (raw body minus signature): {payload_to_hash}")
    current_app.logger.info(f"String to Hash (raw body minus signature): {payload_to_hash}")

    # In sandbox, we hash the payload directly (no passphrase).
    # In production, we append the passphrase.

    if not PAYFAST_SANDBOX and PAYFAST_PASSPHRASE:
        string_to_check = f"{payload_to_hash}&passphrase={PAYFAST_PASSPHRASE}"
    else:
        string_to_check = payload_to_hash

    print(f"Final String for Hashing: {string_to_check}")
    current_app.logger.info(f"Final String for Hashing: {string_to_check}")

    calculated_signature = hashlib.md5(string_to_check.encode('utf-8')).hexdigest()
    
    print(f"Calculated Signature: {calculated_signature}")
    current_app.logger.info(f"Calculated Signature: {calculated_signature}")

    # --- Verification ---
    if calculated_signature != received_signature:
        print("!!! SIGNATURE MISMATCH !!!")
        current_app.logger.error("!!! PayFast ITN Signature Mismatch !!!")
        return "Invalid signature", 400

    print("--- SIGNATURE VERIFIED ---")
    current_app.logger.info("--- PayFast ITN Signature Verified ---")

    # --- Process Payment ---
    # Use request.form to get the decoded data for processing
    data = dict(request.form)
    payment_status = data.get('payment_status')
    email = data.get('custom_str1')
    plan = data.get('custom_str2', 'monthly')
    
    if payment_status == 'COMPLETE' and email:
        pf_subscription_id = (
            data.get('pf_subscription_id') or 
            data.get('subscription_id') or 
            data.get('recurring_transaction_id') or 
            data.get('m_payment_id') or 
            ''
        )
        
        current_app.logger.info(f"Processing COMPLETE payment for {email}, subscription_id: {pf_subscription_id}")
        print(f"Processing COMPLETE payment for {email}, subscription_id: {pf_subscription_id}")
        
        if plan == 'annual':
            subscription_end = datetime.now(timezone.utc) + timedelta(days=365)
        else:
            subscription_end = datetime.now(timezone.utc) + timedelta(days=30)
        
        update_fields = {
            'premium': True,
            'subscription_plan': plan,
            'subscription_start': datetime.now(timezone.utc),
            'subscription_end': subscription_end,
            'payment_amount': data.get('amount_gross', '0.00'), # Use amount_gross from ITN
            'payment_id': data.get('pf_payment_id', ''),
            'payfast_subscription_id': pf_subscription_id,
            'last_payment_date': datetime.now(timezone.utc)
        }
        
        users_collection.update_one({'email': email}, {'$set': update_fields})
        current_app.logger.info(f"User {email} upgraded to premium with {plan} plan")
        
    else:
        current_app.logger.warning(f"Payment status '{payment_status}' for user {email}. No action taken.")
        print(f"Payment status '{payment_status}' for user {email}. No action taken.")
    
    return 'OK', 200
