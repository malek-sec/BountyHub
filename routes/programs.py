from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import Program, Vulnerability

bp = Blueprint('programs', __name__, url_prefix='/programs')


@bp.route('/')
@login_required
def index():
    programs = (Program.query
                .filter_by(user_id=current_user.id)
                .order_by(Program.created_at.desc())
                .all())
    return render_template('programs/index.html', programs=programs)


@bp.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    if request.method == 'GET':
        return render_template('programs/new.html')

    name = request.form.get('name', '').strip()
    if not name:
        flash('Program name is required.', 'error')
        return render_template('programs/new.html')

    raw_url    = request.form.get('policy_url', '').strip() or None
    if raw_url and not raw_url.startswith(('https://', 'http://')):
        flash('Policy URL must start with https:// or http://', 'error')
        return render_template('programs/new.html')
    policy_url = raw_url

    program = Program(
        user_id=current_user.id,
        name=name,
        platform=request.form.get('platform', '').strip() or None,
        scope=request.form.get('scope', '').strip() or None,
        policy_url=policy_url,
    )
    db.session.add(program)
    db.session.commit()
    flash(f'Program "{name}" created successfully.', 'success')
    return redirect(url_for('programs.index'))


@bp.route('/<int:program_id>')
@login_required
def detail(program_id):
    program = Program.query.get_or_404(program_id)
    if program.user_id != current_user.id:
        abort(403)

    vulns = (Vulnerability.query
             .filter_by(program_id=program_id, user_id=current_user.id)
             .order_by(Vulnerability.date_created.desc())
             .all())

    counts = {
        'Critical': sum(1 for v in vulns if v.severity == 'Critical'),
        'High':     sum(1 for v in vulns if v.severity == 'High'),
        'Medium':   sum(1 for v in vulns if v.severity == 'Medium'),
        'Low':      sum(1 for v in vulns if v.severity == 'Low'),
    }
    return render_template('programs/detail.html',
                           program=program, vulns=vulns, counts=counts)
