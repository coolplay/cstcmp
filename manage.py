#!/usr/bin/env python
from app.cstcmp import app, db, User
from flask.ext.migrate import Migrate, MigrateCommand
from flask.ext.script import Manager, Shell

migrate = Migrate(app, db)

manager = Manager(app)


@manager.command
def create_db():
    db.create_all()


def make_context():
    return dict(app=app, db=db, User=User)


manager.add_command('db', MigrateCommand)
manager.add_command('shell', Shell(make_context=make_context))

if __name__ == '__main__':
    manager.run()
