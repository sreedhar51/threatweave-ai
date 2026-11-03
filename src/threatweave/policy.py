"""Restricted policy DSL; never eval arbitrary Python, Rego, or LLM-provided code."""
from .utils import digest, read_yaml

FIELDS={'severity','vpr','environment','business_tag','asset_type','role','criticality',
        'internet_exposure','compounded_exposure','kind','status'}
ACTIONS={'score_add','priority_floor','add_evidence_flag','require_review'}
LEVELS={'info':0,'low':15,'medium':33,'high':50,'critical':66}
FLOORS={'low':15,'medium':30,'high':50,'urgent':75}


def validate_policy(policy):
    if not isinstance(policy,dict) or not isinstance(policy.get('rules'),list):
        raise ValueError('Policy needs rules list')
    if not isinstance(policy.get('policy_id'),str) or not isinstance(policy.get('version'),str):
        raise ValueError('Policy needs policy_id and string version')
    if len(policy['rules'])>50: raise ValueError('Maximum 50 rules per policy')
    seen=set()
    for rule in policy['rules']:
        if not isinstance(rule,dict) or not rule.get('id'): raise ValueError('Rule missing id')
        if rule['id'] in seen: raise ValueError('Duplicate rule ID')
        seen.add(rule['id'])
        when=rule.get('when')
        then=rule.get('then')
        if not isinstance(when,dict) or not isinstance(then,dict):
            raise ValueError('Rules require when/then objects')
        if not when or not then: raise ValueError('Rules cannot have empty when/then')
        if set(when)-FIELDS: raise ValueError(f'Unsupported condition fields: {set(when)-FIELDS}')
        if set(then)-ACTIONS: raise ValueError(f'Unsupported actions: {set(then)-ACTIONS}')
        for field, value in when.items():
            if isinstance(value,(list,dict)) or value is None: raise ValueError('Use scalar condition values only')
            if field=='compounded_exposure' and not isinstance(value,bool):
                raise ValueError('compounded_exposure must be boolean')
        if 'score_add' in then:
            delta=then['score_add']
            if isinstance(delta,bool) or not isinstance(delta,(int,float)) or not -20<=delta<=30:
                raise ValueError('score_add must be a number between -20 and 30')
            # Negative weights require independently supported mitigating evidence (not in MVP).
            if delta<0: raise ValueError('Negative score changes are disabled in MVP')
        if 'priority_floor' in then and then['priority_floor'] not in FLOORS:
            raise ValueError('Invalid priority floor')
        if 'require_review' in then and not isinstance(then['require_review'],bool):
            raise ValueError('require_review must be boolean')
        if 'add_evidence_flag' in then and not isinstance(then['add_evidence_flag'],str):
            raise ValueError('add_evidence_flag must be a string')
    return policy


def load_policy(path):
    return validate_policy(read_yaml(path))


def matches(conditions, context):
    for field,expected in conditions.items():
        actual=context.get(field)
        if actual is None: return False
        if field=='business_tag':
            if str(expected).lower() not in [str(x).lower() for x in actual]: return False
        elif isinstance(expected,str):
            if str(actual).lower()!=expected.lower(): return False
        elif actual!=expected:
            return False
    return True


def priority(score):
    if score>=75: return 'urgent'
    if score>=50: return 'high'
    if score>=30: return 'medium'
    return 'low'


def evaluate_finding(finding, context, policy):
    sev=str(finding.get('severity') or 'info').lower()
    score=float(LEVELS.get(sev,0))
    vpr=finding.get('vpr')
    if vpr is not None:
        score += max(0,min(9.9,float(vpr)))*0.7
    contributions=[]
    flags=[]
    if not finding.get('observed_at'):
        flags.append('last_observed_unknown')
    if not context.get('environment'):
        flags.append('environment_unknown')
    if context.get('mapping_conflict'):
        flags.append('conflicting_cmdb_context')
    for rule in policy['rules']:
        if matches(rule['when'],context):
            before=score
            action=rule['then']
            score+=float(action.get('score_add',0))
            if action.get('priority_floor'):
                score=max(score,FLOORS[action['priority_floor']])
            if action.get('add_evidence_flag'): flags.append(action['add_evidence_flag'])
            if action.get('require_review'): flags.append('policy_review_required')
            contributions.append({'rule_id':rule['id'],'delta':round(score-before,2),
                                  'reason':rule.get('name',rule['id'])})
    score=max(0,min(100,score))
    return {'score':round(score,2),'priority':priority(score),'contributions':contributions,
            'evidence_flags':sorted(set(flags))}
