# app/models.py

from app import db, bcrypt


class User(db.Model):
    __tablename__ = 'tbl_user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(80), nullable=False, default='Active')
    role = db.Column(db.String(80), nullable=False, default='USER_ROLE')
    record_date = db.Column(db.DateTime(timezone=True))
    last_update = db.Column(db.DateTime(timezone=True))

    def __repr__(self):
        return 'User: {}'.format(self.username)

    def save_to_db(self):
        if self.id:
            db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @staticmethod
    def hash_pwd(pwd):
        return bcrypt.generate_password_hash(pwd).decode('utf-8')

    @staticmethod
    def check_pwd(hashed, pwd):
        return bcrypt.check_password_hash(hashed, pwd)

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'role': x.role
            }
        return list(map(lambda x: to_json(x), User.query.all()))

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}


class RevokedTokenModel(db.Model):
    __tablename__ = 'tbl_revoked_token'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120))

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)
