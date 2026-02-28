"""Discovers all routes registered in a Flask application."""
import inspect
from dataclasses import dataclass
from typing import List, Callable, Optional


@dataclass
class RouteInfo:
    path: str
    methods: List[str]
    view_function: Callable
    view_function_name: str
    file_path: Optional[str] = None
    source_code: Optional[str] = None


def discover_flask_routes(app) -> List[RouteInfo]:
    """Extract all routes from a Flask application."""
    routes = []

    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue

        view_func = app.view_functions.get(rule.endpoint)
        if view_func is None:
            continue

        try:
            source = inspect.getsource(view_func)
            file_path = inspect.getfile(view_func)
        except (OSError, TypeError):
            source = None
            file_path = None

        routes.append(RouteInfo(
            path=rule.rule,
            methods=sorted(rule.methods - {"HEAD", "OPTIONS"}),
            view_function=view_func,
            view_function_name=view_func.__name__,
            file_path=file_path,
            source_code=source,
        ))

    return routes