import json

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import FeatureFlag, Vulnerability
from models.feature_flag import require_feature

bp = Blueprint('admin', __name__, url_prefix='/admin')


@bp.route('/features')
@login_required
def feature_admin():
    if current_user.role != 'admin':
        flash('يجب أن تكون مسؤولاً للوصول لهذه الصفحة', 'error')
        return redirect(url_for('vulnerabilities.home'))
    flags = FeatureFlag.query.order_by(FeatureFlag.name).all()
    return render_template('admin_features.html', flags=flags)


@bp.route('/features/<int:flag_id>/toggle', methods=['POST'])
@login_required
def toggle_feature(flag_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    flag         = FeatureFlag.query.get_or_404(flag_id)
    flag.enabled = not flag.enabled
    db.session.commit()
    return jsonify({'success': True, 'enabled': flag.enabled})


@bp.route('/features/<int:flag_id>/rollout', methods=['POST'])
@login_required
def update_rollout(flag_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    flag                    = FeatureFlag.query.get_or_404(flag_id)
    percentage              = int(request.json.get('percentage', 0))
    flag.rollout_percentage = max(0, min(100, percentage))
    db.session.commit()
    return jsonify({'success': True, 'percentage': flag.rollout_percentage})


@bp.route('/bulk/delete', methods=['POST'])
@login_required
@require_feature('bulk_operations')
def bulk_delete():
    ids = request.json.get('ids', [])
    deleted = Vulnerability.query.filter(
        Vulnerability.id.in_(ids),
        Vulnerability.user_id == current_user.id,
    ).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'success': True, 'deleted': deleted})


@bp.route('/bulk/status', methods=['POST'])
@login_required
@require_feature('bulk_operations')
def bulk_status():
    ids        = request.json.get('ids', [])
    new_status = request.json.get('status', 'open')
    updated = Vulnerability.query.filter(
        Vulnerability.id.in_(ids),
        Vulnerability.user_id == current_user.id,
    ).update({'status': new_status}, synchronize_session=False)
    db.session.commit()
    return jsonify({'success': True, 'updated': updated})
