"""应用装配冒烟测试。"""


def test_app_boots() -> None:
    from app.app import create_app

    app = create_app()
    assert app is not None
