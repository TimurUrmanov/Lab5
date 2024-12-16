from flask import Flask, request, jsonify
from flask_smorest import Api, Blueprint
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, get_jwt
)
from datetime import timedelta
from db import db
from models import UserModel, ItemModel
from schemas import UserSchema, ItemSchema, ItemUpdateSchema

app = Flask(__name__)
app.config["PROPAGATE_EXCEPTIONS"] = True
app.config["API_TITLE"] = "Store REST API"
app.config["API_VERSION"] = "v1"
app.config["OPENAPI_VERSION"] = "3.0.3"
app.config["JWT_SECRET_KEY"] = "supersecretkey"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
api = Api(app)
jwt = JWTManager(app)

# Store revoked tokens
token_blocklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload["jti"] in token_blocklist

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({
        "message": "The token has been revoked.",
        "error": "token_revoked"
    }), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return (
        jsonify({"message": "The token has expired.", "error": "token_expired"}),
        401,
    )

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return (
        jsonify({"message": "Signature verification failed.", "error": "invalid_token"}),
        401,
    )

@jwt.unauthorized_loader
def missing_token_callback(error):
    return (
        jsonify({
            "description": "Request does not contain an access token.",
            "error": "authorization_required",
        }),
        401,
    )

blp = Blueprint("Auth", __name__, description="Authentication operations")

@blp.route("/login")
class Login(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        user = UserModel.query.filter_by(username=user_data["username"]).first()
        
        if user and user.check_password(user_data["password"]):
            access_token = create_access_token(identity=user.id)
            return jsonify(access_token=access_token)
        return jsonify({"message": "Invalid credentials."}), 401

@blp.route("/logout")
class Logout(MethodView):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]  # Unique identifier for the JWT
        token_blocklist.add(jti)
        return jsonify({"message": "Successfully logged out."})

api.register_blueprint(blp)

# Protecting existing endpoints
blp_item = Blueprint("Items", __name__, description="Operations on items")

@blp_item.route("/item/<string:item_id>")
class Item(MethodView):
    @jwt_required()
    @blp_item.response(200, ItemSchema)
    def get(self, item_id):
        item = ItemModel.query.get_or_404(item_id)
        return item

    @jwt_required()
    def delete(self, item_id):
        item = ItemModel.query.get_or_404(item_id)
        db.session.delete(item)
        db.session.commit()
        return {"message": "Item deleted."}

    @jwt_required()
    @blp_item.arguments(ItemUpdateSchema)
    @blp_item.response(200, ItemSchema)
    def put(self, item_data, item_id):
        item = ItemModel.query.get_or_404(item_id)

        if item:
            item.price = item_data["price"]
            item.name = item_data["name"]
        else:
            item = ItemModel(**item_data)

        db.session.add(item)
        db.session.commit()

        return item

@blp_item.route("/item")
class ItemList(MethodView):
    @jwt_required()
    @blp_item.response(200, ItemSchema(many=True))
    def get(self):
        return ItemModel.query.all()

    @jwt_required()
    @blp_item.arguments(ItemSchema)
    @blp_item.response(201, ItemSchema)
    def post(self, item_data):
        item = ItemModel(**item_data)

        try:
            db.session.add(item)
            db.session.commit()
        except SQLAlchemyError:
            abort(500, message="An error occurred while inserting the item.")

        return item

api.register_blueprint(blp_item)

if __name__ == "__main__":
    db.init_app(app)
    app.run(debug=True)
