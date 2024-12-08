from flask import Flask, jsonify
from flask_smorest import Api
from flask_jwt_extended import JWTManager
import os
from blocklist import BLOCKLIST

from db import db

from resources.item import blp as itemBlueprint
from resources.store import blp as storeBlueprint
from resources.tag import blp as tagBlueprint
from resources.user import blp as userBlueprint

app = Flask(__name__)
def create_app(db_url=None):
  
  app.config["API_TITLE"] = "Flask REST API"
  app.config["API_VERSION"] = "v1"
  app.config["OPENAPI_VERSION"] = "3.0.3"
  app.config["SQLALCHEMY_DATABASE_URI"] = db_url or os.getenv("DATABASE_URL", "sqlite:///data.db")
  app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
  db.init_app(app)

  app.config["JWT_SECRET_KEY"] = "jhon"
  jwt = JWTManager(app)

  @jwt.token_in_blocklist_loader
  def check_if_token_in_blocklist(jwt_header, jwt_payload):
    return jwt_payload["jti"] in BLOCKLIST
  
  @jwt.revoked_token_loader
  def refoked_token_callback(jwt_header, jwt_payload):
    return(
      jsonify({
        "description": "The token has been revoked.",
        "error": "token_revoked"
      }), 401
    )

  @jwt.expired_token_loader
  def expired_token_callback(jwt_header, jwt_payload):
    return (
      jsonify({"message" : "The token has expired.", "error" : "token expired"}),
      401
    )

  @jwt.invalid_token_loader
  def invalid_token_callback(error):
    return (
      jsonify({"message": "Signature verification failed.", "error": "invalid_token"}),
      401
    )

  @jwt.unauthorized_loader
  def missing_token_callback(error):
    return (
      jsonify({
        "message": "Request does not contain an access token.",
        "error": "authorization_required"
      })
    )

  with app.app_context():
    db.create_all()

  api = Api(app)

  api.register_blueprint(storeBlueprint)
  api.register_blueprint(itemBlueprint)
  api.register_blueprint(tagBlueprint)
  api.register_blueprint(userBlueprint)
  return app

if __name__ == "__main__":
  app = create_app()
  app.run(debug=True)