import capa.render.utils as rutils


def render_verbose(doc):
    ostream = rutils.StringIO()

    for rule in rutils.capability_rules(doc):
        ostream.writeln(rutils.bold(rule['meta']['name']))

    return ostream.getvalue()
