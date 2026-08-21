class CvssService:
    @staticmethod
    def calculate(form_data: dict) -> float:
        av_map     = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
        ac_map     = {'L': 0.77, 'H': 0.44}
        pr_map     = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        ui_map     = {'N': 0.85, 'R': 0.62}
        impact_map = {'H': 0.56, 'L': 0.22, 'N': 0.0}

        av = av_map.get(form_data.get('av', 'N'), 0.85)
        ac = ac_map.get(form_data.get('ac', 'L'), 0.77)
        pr = pr_map.get(form_data.get('pr', 'N'), 0.85)
        ui = ui_map.get(form_data.get('ui', 'N'), 0.85)
        c  = impact_map.get(form_data.get('c', 'H'), 0.56)
        i  = impact_map.get(form_data.get('i', 'H'), 0.56)
        a  = impact_map.get(form_data.get('a', 'H'), 0.56)

        exploitability = 8.22 * av * ac * pr * ui
        impact         = 1 - ((1 - c) * (1 - i) * (1 - a))

        if impact <= 0:
            return 0.0

        if form_data.get('scope', 'U') == 'C':
            impact_score = 7.52 * (impact - 0.029) - 3.25 * pow(impact - 0.02, 15)
        else:
            impact_score = 6.42 * impact

        if impact_score <= 0:
            return 0.0

        return round(min(exploitability + impact_score, 10.0), 1)

    @staticmethod
    def get_severity(score: float) -> str:
        if score >= 9.0:   return "Critical"
        elif score >= 7.0: return "High"
        elif score >= 4.0: return "Medium"
        elif score > 0.0:  return "Low"
        return "Informational"
