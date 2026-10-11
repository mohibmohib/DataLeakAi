def explain(risk: dict, decision: dict) -> str:
    lines = [f"Decision: {decision['action']}",
             f"Risk Score: {risk['score']}/100 ({risk['level']})",
             f"Category: {risk['category']}",
             f"Reason: {decision['reason']}", "", "Risk factors:"]
    lines += [f"  {i}. {f}" for i, f in enumerate(risk["factors"], 1)] or ["  1. No risk indicators found"]
    return "\n".join(lines)
