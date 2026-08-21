class PayoutService:

    CURRENCIES = ['USD', 'EUR', 'GBP', 'SAR']
    STATUSES   = ['unpaid', 'pending', 'paid', 'n/a']

    @staticmethod
    def update(bug, payout: float, currency: str, bounty_status: str) -> dict:
        """Validate and apply payout fields. Does NOT commit."""
        if payout < 0:
            raise ValueError("Payout must be >= 0")
        if currency not in PayoutService.CURRENCIES:
            raise ValueError(
                f"Invalid currency '{currency}'. Must be one of: "
                + ", ".join(PayoutService.CURRENCIES)
            )
        if bounty_status not in PayoutService.STATUSES:
            raise ValueError(
                f"Invalid bounty_status '{bounty_status}'. Must be one of: "
                + ", ".join(PayoutService.STATUSES)
            )
        bug.payout        = payout
        bug.currency      = currency
        bug.bounty_status = bounty_status
        return {
            'payout':        bug.payout,
            'currency':      bug.currency,
            'bounty_status': bug.bounty_status,
        }

    @staticmethod
    def earnings_summary(user_id: int) -> dict:
        """Aggregate payout stats for a user using SQL-level aggregation."""
        from extensions import db
        from models.vulnerability import Vulnerability

        V = Vulnerability

        def _sum(status):
            row = (
                db.session.query(
                    db.func.coalesce(db.func.sum(V.payout), 0.0)
                )
                .filter(V.user_id == user_id, V.bounty_status == status)
                .one()
            )
            return float(row[0])

        def _count(status):
            return (
                db.session.query(db.func.count(V.id))
                .filter(V.user_id == user_id, V.bounty_status == status)
                .scalar()
            )

        total_earned = _sum('paid')

        # by_severity — paid earnings per severity level
        sev_rows = (
            db.session.query(
                V.severity,
                db.func.coalesce(db.func.sum(V.payout), 0.0)
            )
            .filter(V.user_id == user_id, V.bounty_status == 'paid')
            .group_by(V.severity)
            .all()
        )
        by_severity = {'Critical': 0.0, 'High': 0.0, 'Medium': 0.0, 'Low': 0.0}
        for sev, total in sev_rows:
            if sev in by_severity:
                by_severity[sev] = float(total)

        # by_program — paid earnings per program name
        from models.program import Program
        prog_rows = (
            db.session.query(
                Program.name,
                db.func.coalesce(db.func.sum(V.payout), 0.0)
            )
            .join(Program, V.program_id == Program.id)
            .filter(V.user_id == user_id, V.bounty_status == 'paid')
            .group_by(Program.name)
            .order_by(db.func.sum(V.payout).desc())
            .all()
        )
        by_program = [{'name': name, 'total': float(total)} for name, total in prog_rows]

        return {
            'total_earned':  total_earned,
            'by_severity':   by_severity,
            'by_program':    by_program,
            'unpaid_count':  _count('unpaid'),
            'unpaid_total':  _sum('unpaid'),
            'pending_count': _count('pending'),
            'pending_total': _sum('pending'),
        }
