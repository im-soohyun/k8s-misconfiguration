from flask import Blueprint, jsonify, request
from http import HTTPStatus

from services.repo_service import RepoService
from services.scan_service import ScanService


scanController = Blueprint("scan", __name__)


def _perform_scan(repo_url: str):
    if not repo_url:
        return jsonify({"error": "repo-url parameter is required"}), HTTPStatus.BAD_REQUEST

    repo_service = RepoService()
    scan_service = ScanService()

    clone_path = None
    try:
        clone_path = repo_service.clone_repo(repo_url)
        scan_result = scan_service.scan_repository(clone_path)

        response = {
            "repoUrl": repo_url,
            "stats": {
                "filesScanned": scan_result["filesScanned"],
                "findings": len(scan_result["findings"]),
            },
            "findings": scan_result["findings"],
        }
        return jsonify(response), HTTPStatus.OK
    except ValueError as exc:
        return jsonify({"error": str(exc)}), HTTPStatus.BAD_REQUEST
    except Exception as exc:
        return jsonify({"error": f"Unexpected error: {exc}"}), HTTPStatus.INTERNAL_SERVER_ERROR
    finally:
        if clone_path:
            try:
                repo_service.cleanup(clone_path)
            except Exception:
                pass


@scanController.get("/scan")
def scan_repository_get_query():
    repo_url = request.args.get("repo-url")
    return _perform_scan(repo_url)
