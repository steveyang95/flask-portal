import uuid
import os


class Config:
    # Define the application directory
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # Application threads. A common general assumption is
    # using 2 per available processor cores - to handle
    # incoming requests using one and performing background
    # operations using the other.
    THREADS_PER_PAGE = 2

    # Enable protection agains *Cross-site Request Forgery (CSRF)*
    CSRF_ENABLED = True

    # Use a secure, unique and absolutely secret key for
    # signing the data.
    CSRF_SESSION_KEY = "secret"

    # Secret key for signing cookies
    SECRET_KEY = str(uuid.uuid4())

    GOOGLE_ID = os.environ['GOOGLE_ID']
    GOOGLE_SECRET = os.environ['GOOGLE_SECRET']
    GOOGLE_SCOPE = 'email https://www.googleapis.com/auth/admin.directory.group.readonly'

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True


class HerokuConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    # 'testing': TestingConfig,
    # 'production': ProductionConfig,
    'heroku': HerokuConfig,
    # 'unix': UnixConfig,

    'default': DevelopmentConfig
}
