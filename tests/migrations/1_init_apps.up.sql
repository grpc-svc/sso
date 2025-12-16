INSERT INTO apps (id, name, secret)
VALUES (1, 'Test', 'supersecret')
    ON CONFLICT DO NOTHING;