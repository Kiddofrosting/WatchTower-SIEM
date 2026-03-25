// docker/mongo-init.js
// Creates the watchtower database user on first startup

db = db.getSiblingDB('watchtower');

db.createUser({
  user: 'watchtower_user',
  pwd: 'watchtowerpass',
  roles: [
    { role: 'readWrite', db: 'watchtower' },
    { role: 'dbAdmin', db: 'watchtower' },
  ],
});

print('MongoDB: watchtower_user created successfully');
