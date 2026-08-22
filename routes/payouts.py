import json

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from extensions import db
from models import ActivityLog, Vulnerability
from services.payout_service import PayoutService

bp = Blueprint('payouts', __name__, url_prefix='/api')


@bp.route('/vulnerability/<int:bug_id>/payout', methods=['POST'])
@login_required
def update_payout(bug_id):
    bug = Vulnerability.query.get_or_404(bug_id)
    if bug.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403

    body = request.get_json(silent=True) or {}
    try:
        payout = float(body.get('payout', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid payout value — must be a number'}), 400
    currency      = body.get('currency', 'USD')
    bounty_status = body.get('bounty_status', 'unpaid')

    try:
        PayoutService.update(bug, payout, currency, bounty_status)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    db.session.commit()

    log = ActivityLog(
        user_id=current_user.id,
        action='payout_updated',
        vulnerability_id=bug.id,
        details=json.dumps({
            'payout':        bug.payout,
            'currency':      bug.currency,
            'bounty_status': bug.bounty_status,
        }),
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({
        'success':       True,
        'payout':        bug.payout,
        'currency':      bug.currency,
        'bounty_status': bug.bounty_status,
    }), 200


@bp.route('/stats/earnings', methods=['GET'])
@login_required
def earnings_stats():
    summary = PayoutService.earnings_summary(current_user.id)
    return jsonify(summary), 200
