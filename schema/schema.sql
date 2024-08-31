CREATE TABLE certs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    der BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
