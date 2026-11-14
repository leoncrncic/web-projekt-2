import express from "express";
import Database from "better-sqlite3";
import path from "node:path";
import { randomUUID } from "node:crypto";


const app = express();
const db = new Database(":memory:");

app.use(express.json());
app.use(express.static(path.join(process.cwd(), "public")));

//Testna baza
db.exec(`
    CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
    );

    INSERT INTO users (username, password, role) VALUES
    ('admin', 'admin123', 'administrator'),
    ('pero', 'pero123', 'korisnik'),
    ('marko', 'marko123', 'korisnik'),
    ('ana', 'ana123', 'korisnik'),
    ('lana', 'lana123', 'korisnik');
    `);


interface User {
    id: number;
    username: string;
    password: string;
    role: string;
}

app.post("/api/sql-injection", (req, res) => {
    const {username, password, vulnerable} = req.body;

    if (typeof username !== "string" || typeof password !== "string" || typeof vulnerable !== "boolean") {
        res.status(400).json({error: "Neispravni podaci."});
        return;
    }

    
    try {
        let user: User | undefined;
        let sql: string;

        if(vulnerable) {
            //Nesigurno
            sql = `SELECT * FROM users
                   WHERE username = '${username}'
                   AND password = '${password}'`;

            user = db.prepare(sql).get() as User | undefined;
        } 
        else {
            //Sigurno
            sql = `SELECT * FROM users
                   WHERE username = ?
                   AND password = ?`;
                
            user = db.prepare(sql).get(username, password) as User | undefined
        }

        if (user) {
            res.json({
                success: true,
                message: "Prijava uspjesna!",
                user: {
                    username: user.username,
                    role: user.role
                }, 
                sql
            });
        } else {
            res.json({
                success: false,
                message: "Pogresno ime ili lozinka",
                sql
            })
        }
       
    } catch {
        res.json({
            success: false,
            message: "Upit nije uspjesan"
        });
    }
});



interface BruteForceSession {
    vulnerable: boolean;
    finished: boolean;
    attempts: number;
    createdAt: number;
}

interface TestAccount {
    failedAttempts: number;
    lockedUntil: number;
}

const bruteForceSessions = new Map<string, BruteForceSession>();

const testUsername = "leon";
const testPassword = "leon123";
const maxAttempts = 3;
const lockDuration = 5 * 60 * 1000;

const testAccount: TestAccount = {
    failedAttempts: 0,
    lockedUntil: 0
};

const allowedPasswords = [
    "123456",
    "password",
    "qwerty",
    "abc123",
    "leon123"
];

app.post("/api/brute-force/start", (req, res) => {
    const { vulnerable } = req.body ?? {};

    if (typeof vulnerable !== "boolean") {
        res.status(400).json({ error: "Neispravni podaci" });
        return;
    }

    const now = Date.now();

    for (const [id, session] of bruteForceSessions) {
        if (now - session.createdAt > 10 * 60 * 1000) {
            bruteForceSessions.delete(id);
        }
    }

    const sessionId = randomUUID();

    bruteForceSessions.set(sessionId, {
        vulnerable,
        finished: false,
        attempts: 0,
        createdAt: now
    });

    res.json({
        sessionId,
        username: testUsername,
        vulnerable
    });
});

app.post("/api/brute-force/attempt", (req, res) => {
    const { sessionId, password } = req.body ?? {};

    if (typeof sessionId !== "string" || typeof password !== "string") {
        res.status(400).json({ error: "Neispravni podaci" });
        return;
    }

    const session = bruteForceSessions.get(sessionId);

    if (!session || Date.now() - session.createdAt > 600000) {
        res.status(404).json({ error: "Testna sesija ne postoji" });
        return;
    }

    if (!allowedPasswords.includes(password)) {
        res.status(400).json({ error: "Nepoznata testna lozinka" });
        return;
    }

    if (session.finished || session.attempts >= 5) {
        res.status(409).json({ error: "Demonstracija je zavrsena" });
        return;
    }

    session.attempts++;


    if (session.vulnerable) {
        if (password === testPassword) {
            session.finished = true;

            res.json({
                status: "success",
                message: "Lozinka je pogodena!"
            });
            return;
        }

        res.json({
            status: "failed",
            message: "Pogresna lozinka."
        });
        return;
    }

    const now = Date.now();

    if (testAccount.lockedUntil > now) {
        session.finished = true;

        const seconds = Math.ceil((testAccount.lockedUntil - now) / 1000);

        res.json({
            status: "locked",
            message: `Racun je zakljucan jos ${seconds} sekundi.`
        });
        return;
    }

    if (testAccount.lockedUntil !== 0) {
        testAccount.failedAttempts = 0;
        testAccount.lockedUntil = 0;
    }

    if (password === testPassword) {
        testAccount.failedAttempts = 0;
        session.finished = true;

        res.json({
            status: "success",
            message: "Prijava uspjesna!"
        });
        return;
    }

    testAccount.failedAttempts++;

    if (testAccount.failedAttempts >= maxAttempts) {
        testAccount.lockedUntil = now + lockDuration;
        session.finished = true;

        res.json({
            status: "locked",
            message: "Tri pogresna pokusaja. Racun je zakljucan na 5 minuta."
        });
        return;
    }

    res.json({
        status: "failed",
        message: `Pogresna lozinka (${testAccount.failedAttempts}/${maxAttempts}).`
    });
});


app.post("/api/brute-force/reset", (req, res) => {
    testAccount.failedAttempts = 0;
    testAccount.lockedUntil = 0;
    bruteForceSessions.clear();

    res.json({
        message: "Testni racun je resetiran."
    });
});


const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server: http://localhost:${PORT}`);
});