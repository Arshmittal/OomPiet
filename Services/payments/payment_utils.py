from datetime import datetime,timedelta, timezone

from flask import current_app


def pay_notify_handler(data, users_collection):
    """Helper function to process PayFast ITN data"""
    payment_status = data.get('payment_status')
    email = data.get('custom_str1')
    plan = data.get('custom_str2', 'monthly')
    
    if payment_status == 'COMPLETE' and email:
        # Get subscription ID from different possible fields
        pf_subscription_id = (
            data.get('pf_subscription_id') or 
            data.get('subscription_id') or 
            data.get('recurring_transaction_id') or 
            data.get('m_payment_id') or 
            ''
        )
        
        current_app.logger.info(f"Processing payment for {email}, subscription_id: {pf_subscription_id}")
        
        # Calculate subscription end date
        if plan == 'annual':
            subscription_end = datetime.now(timezone.utc) + timedelta(days=365)
        else:
            subscription_end = datetime.now(timezone.utc) + timedelta(days=30)
        
        # Update user record
        update_fields = {
            'premium': True,
            'subscription_plan': plan,
            'subscription_start': datetime.now(timezone.utc),
            'subscription_end': subscription_end,
            'payment_amount': data.get('amount', '0.00'),
            'payment_id': data.get('pf_payment_id', ''),
            'last_payment_date': datetime.now(timezone.utc)
        }
        
        if pf_subscription_id:
            update_fields['payfast_subscription_id'] = pf_subscription_id
            current_app.logger.info(f"Subscription ID captured: {pf_subscription_id}")
        else:
            current_app.logger.warning(f"No subscription ID found in ITN data for {email}")
        
        users_collection.update_one({'email': email}, {'$set': update_fields})
        
        return {'success': True, 'subscription_id': pf_subscription_id}
    
    return {'success': False, 'error': 'Invalid payment status or missing email'}