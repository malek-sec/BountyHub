import base64
import datetime
import json
import mimetypes
import os
import re

from flask import (Blueprint, abort, current_app, flash, make_response,
                   redirect, render_template, request, url_for)
from flask_login import current_user, login_required
from sqlalchemy import func

try:
    from weasyprint import HTML as WeasyHTML
    _PDF_AVAILABLE = True
except Exception:  # ImportError, or OSError from missing Pango/Cairo shared libs
    WeasyHTML = None
    _PDF_AVAILABLE = False

from extensions import db
from models import ActivityLog, FeatureFlag, Program, ScanJob, Vulnerability
from models.feature_flag import require_feature
from services.cvss_service import CvssService
from services.notify_service import NotifyService
from services.upload_service import UploadService

bp = Blueprint('vulnerabilities', __name__)


@bp.route('/')
@login_required
def home():
    from services.payout_service import PayoutService

    uid    = current_user.id
    base_q = Vulnerability.query.filter_by(user_id=uid)
    recent = (Vulnerability.query
              .filter_by(user_id=uid)
              .order_by(Vulnerability.date_created.desc())
              .limit(5).all())
    stats = {
        'total':    base_q.count(),
        'critical': base_q.filter_by(severity='Critical').count(),
        'high':     base_q.filter_by(severity='High').count(),
        'medium':   Vulnerability.query.filter_by(user_id=uid, severity='Medium').count(),
        'low':      Vulnerability.query.filter_by(user_id=uid, severity='Low').count(),
    }
    earnings = PayoutService.earnings_summary(uid)
    stats['total_earned']  = earnings['total_earned']
    stats['unpaid_total']  = earnings['unpaid_total']
    stats['pending_total'] = earnings['pending_total']

    current_year = datetime.datetime.utcnow().year
    year_start   = datetime.datetime(current_year, 1, 1)
    stats['earned_this_year'] = (
        db.session.query(func.coalesce(func.sum(Vulnerability.payout), 0.0))
        .filter(Vulnerability.user_id == uid,
                Vulnerability.bounty_status == 'paid',
                Vulnerability.date_created >= year_start)
        .scalar()) or 0.0
    stats['scans_completed'] = ScanJob.query.filter_by(user_id=uid, status='completed').count()
    stats['active_programs'] = Program.query.filter_by(user_id=uid, status='active').count()

    activity = (ActivityLog.query
                .filter_by(user_id=uid)
                .order_by(ActivityLog.timestamp.desc())
                .limit(6).all())

    return render_template('index.html',
                           stats=stats, recent=recent,
                           activity=activity, current_year=current_year)


@bp.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'GET':
        programs = (Program.query
                    .filter_by(user_id=current_user.id, status='active')
                    .order_by(Program.name)
                    .all())
        return render_template('submit.html', programs=programs)

    cvss_data = {
        'av':    request.form.get('av'),
        'ac':    request.form.get('ac', 'L'),
        'pr':    request.form.get('pr', 'N'),
        'ui':    request.form.get('ui', 'N'),
        'c':     request.form.get('c', 'H'),
        'i':     request.form.get('i', 'H'),
        'a':     request.form.get('a', 'H'),
        'scope': request.form.get('scope', 'U'),
    }
    score    = CvssService.calculate(cvss_data)
    severity = CvssService.get_severity(score)

    file     = request.files.get('poc_image')
    filename = ""
    if file and file.filename:
        try:
            filename = UploadService.save(
                file, current_app.config['UPLOAD_FOLDER'])
        except ValueError as exc:
            flash(str(exc), 'error')
            return render_template('submit.html')

    tags = json.dumps(
        [t.strip() for t in request.form.get('tags', '').split(',') if t.strip()])

    raw_pid    = request.form.get('program_id', '').strip()
    program_id = None
    if raw_pid:
        prog = Program.query.filter_by(
            id=int(raw_pid), user_id=current_user.id).first()
        if prog:
            program_id = prog.id

    payout        = float(request.form.get('payout') or 0)
    currency      = request.form.get('currency', 'USD')
    bounty_status = request.form.get('bounty_status', 'unpaid')

    new_bug = Vulnerability(
        title=request.form.get('title'),
        severity=severity,
        cvss_score=score,
        steps=request.form.get('steps'),
        impact=request.form.get('impact'),
        remediation=request.form.get('remediation', ''),
        poc_image=filename,
        tags=tags,
        user_id=current_user.id,
        program_id=program_id,
        payout=payout,
        currency=currency,
        bounty_status=bounty_status,
        status='open',
    )
    db.session.add(new_bug)
    db.session.commit()

    NotifyService.notify_all(
        f"🚨 <b>New Vulnerability Logged!</b>\n"
        f"🎯 <b>Target/Title:</b> {new_bug.title}\n"
        f"🔥 <b>Severity:</b> {severity}\n"
        f"📊 <b>CVSS:</b> {score}"
    )

    log = ActivityLog(
        user_id=current_user.id,
        action='created',
        vulnerability_id=new_bug.id,
        details=json.dumps({'title': new_bug.title, 'severity': severity}),
    )
    db.session.add(log)
    db.session.commit()

    flash(f'✅ تم إضافة الثغرة بنجاح - الخطورة: {severity}', 'success')
    return redirect(url_for('vulnerabilities.preview', bug_id=new_bug.id))


@bp.route('/archive')
@login_required
def archive():
    q               = request.args.get('q', '')
    severity_filter = request.args.get('severity', 'all')
    status_filter   = request.args.get('status', 'all')
    sort_by         = request.args.get('sort', 'newest')
    pid             = request.args.get('program', '').strip()

    query = Vulnerability.query.filter_by(user_id=current_user.id)

    if q:
        query = query.filter(Vulnerability.title.contains(q))
    if severity_filter != 'all':
        query = query.filter_by(severity=severity_filter)
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    if pid:
        try:
            query = query.filter_by(program_id=int(pid))
        except (ValueError, TypeError):
            pass

    if sort_by == 'newest':
        query = query.order_by(Vulnerability.date_created.desc())
    elif sort_by == 'oldest':
        query = query.order_by(Vulnerability.date_created.asc())
    elif sort_by == 'severity':
        query = query.order_by(Vulnerability.cvss_score.desc())
    elif sort_by == 'title':
        query = query.order_by(Vulnerability.title.asc())

    programs = (Program.query
                .filter_by(user_id=current_user.id)
                .order_by(Program.name)
                .all())

    return render_template(
        'archive.html',
        bugs=query.all(), q=q,
        severity_filter=severity_filter,
        status_filter=status_filter,
        sort_by=sort_by,
        programs=programs,
        program_filter=pid,
    )


@bp.route('/payouts')
@login_required
def payouts():
    from services.payout_service import PayoutService
    uid     = current_user.id
    summary = PayoutService.earnings_summary(uid)
    bugs    = (Vulnerability.query
               .filter_by(user_id=uid)
               .filter(Vulnerability.bounty_status.in_(['paid', 'pending', 'unpaid']))
               .order_by(Vulnerability.date_created.desc())
               .all())
    return render_template('payouts.html', summary=summary, bugs=bugs)


@bp.route('/preview/<int:bug_id>')
@login_required
def preview(bug_id):
    bug = Vulnerability.query.get_or_404(bug_id)
    if bug.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('vulnerabilities.home'))
    tags = json.loads(bug.tags) if bug.tags else []
    return render_template('preview.html', bug=bug, tags=tags)


@bp.route('/vulnerability/<int:bug_id>/delete', methods=['POST'])
@login_required
def delete_vulnerability(bug_id):
    bug = Vulnerability.query.get_or_404(bug_id)
    if bug.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('vulnerabilities.archive'))

    ActivityLog.query.filter_by(vulnerability_id=bug_id).delete()
    db.session.delete(bug)
    db.session.commit()

    flash('✅ تم حذف الثغرة بنجاح', 'success')
    return redirect(url_for('vulnerabilities.archive'))


@bp.route('/timeline')
@login_required
def timeline():
    from collections import defaultdict

    sev_filter = request.args.get('severity', 'all')
    pid        = request.args.get('program', '').strip()

    query = Vulnerability.query.filter_by(user_id=current_user.id)
    if sev_filter != 'all':
        query = query.filter_by(severity=sev_filter)
    if pid:
        try:
            query = query.filter_by(program_id=int(pid))
        except (ValueError, TypeError):
            pass

    bugs     = query.order_by(Vulnerability.date_created.desc()).all()
    programs = (Program.query.filter_by(user_id=current_user.id)
                .order_by(Program.name).all())

    monthly: dict = defaultdict(
        lambda: {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    )
    for bug in bugs:
        key = bug.date_created.strftime('%Y-%m')
        sev = bug.severity if bug.severity in ('Critical', 'High', 'Medium', 'Low') else 'Low'
        monthly[key][sev] += 1

    monthly_data = [
        {
            'month':    m,
            'Critical': monthly[m]['Critical'],
            'High':     monthly[m]['High'],
            'Medium':   monthly[m]['Medium'],
            'Low':      monthly[m]['Low'],
            'total':    sum(monthly[m].values()),
        }
        for m in sorted(monthly)
    ]
    max_monthly  = max((m['total'] for m in monthly_data), default=1)
    total_earned = sum(b.payout or 0.0 for b in bugs)

    return render_template('timeline.html',
        bugs=bugs,
        programs=programs,
        severity_filter=sev_filter,
        program_filter=pid,
        monthly_data=monthly_data,
        max_monthly=max_monthly,
        total_earned=total_earned,
    )


@bp.route('/export/<int:bug_id>')
@login_required
@require_feature('pdf_export')
def export_pdf(bug_id):
    if not _PDF_AVAILABLE:
        flash('PDF export requires weasyprint — pip install weasyprint', 'error')
        return redirect(url_for('vulnerabilities.preview', bug_id=bug_id))

    bug = Vulnerability.query.get_or_404(bug_id)
    if bug.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('vulnerabilities.home'))

    # Allowlist sanitisation + date, so two findings with similar titles
    # (or repeat exports across days) never produce the same filename.
    safe_name = re.sub(r'[^A-Za-z0-9]+', '_', bug.title or 'report').strip('_')[:40] or 'report'
    stamp     = (bug.date_updated or bug.date_created
                 or datetime.datetime.utcnow()).strftime('%Y-%m-%d_%H%M')
    tags      = json.loads(bug.tags) if bug.tags else []

    # H-5: embed PoC image as a base64 data URI — no file:// URIs for WeasyPrint.
    img_data_uri = None
    if bug.poc_image:
        _uploads_root = os.path.realpath(
            os.path.join(current_app.root_path, 'static', 'uploads'))
        _img_abs = os.path.realpath(
            os.path.join(_uploads_root, bug.poc_image))
        if _img_abs.startswith(_uploads_root + os.sep) and os.path.isfile(_img_abs):
            _mime, _ = mimetypes.guess_type(_img_abs)
            _mime    = _mime if _mime and _mime.startswith('image/') else 'image/png'
            with open(_img_abs, 'rb') as _fh:
                _b64 = base64.b64encode(_fh.read()).decode()
            img_data_uri = f"data:{_mime};base64,{_b64}"

    html = render_template('pdf_report.html',
                           bug=bug, img_data_uri=img_data_uri, tags=tags)
    try:
        pdf = WeasyHTML(string=html).write_pdf()
    except Exception:
        current_app.logger.error(
            'WeasyPrint render failed for vulnerability %s', bug.id, exc_info=True)
        abort(503)

    log = ActivityLog(user_id=current_user.id, action='exported',
                      vulnerability_id=bug.id)
    db.session.add(log)
    db.session.commit()

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = (
        f'attachment; filename="Report_{safe_name}_{stamp}.pdf"')
    return response
