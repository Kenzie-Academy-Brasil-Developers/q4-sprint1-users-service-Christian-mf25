import express from 'express';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import * as yup from 'yup';
import { v4 } from 'uuid';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express();
const port = process.env.PORT;
const secret = process.env.SECRET_KEY;
const expireTime = process.env.EXPIRES_IN;
const users = [
  {
    uuid: '8828139a-5bd4-414d-bc93-71ac0a310b70',
    username: 'Christian',
    age: 24,
    email: 'chris@email.com',
    password: '$2b$10$ycUqzkiYNIxIZ.53LOPsLOA3gpSTC9w6XbtsfmusLIedn3L4Lr/Pu',
    createdOn: 'Fri Mar 18 2022 19:58:14 GMT-0300 (Horário Padrão de Brasília)',
  },
];

app.use(express.json());

const userShape = yup.object().shape({
  createdOn: yup.string().default(() => Date()),
  password: yup.string().required(),
  email: yup.string().email().required(),
  age: yup.number().integer().min(0).required(),
  username: yup.string().required(),
  uuid: yup.string().default(() => v4()),
});

const loginShape = yup.object().shape({
  password: yup.string().required(),
  email: yup.string().email().required(),
  username: yup.string().required(),
});

const updatePasswordShape = yup.object().shape({
  password: yup.string().required(),
});

const validateShape = (shape) => async (req, res, next) => {
  try {
    const valid = await shape.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });
    req.valid = valid;
    return next();
  } catch (e) {
    return res.status(422).json({ error: e.errors });
  }
};

const checkLoginData = (req, res, next) => {
  const { email, username } = req.body;

  const checkEmail = users.find((item) => item.email === email);
  const checkUsername = users.find((item) => item.username === username);

  if (!checkEmail || !checkUsername) {
    return res.status(404).json({ error: 'user not found' });
  }

  req.user = checkEmail;

  return next();
};

const tokenGenerator = (req, _, next) => {
  const token = jwt.sign(
    {
      email: req.body.email,
      username: req.body.username,
      password: req.body.password,
    },
    secret,
    {
      expiresIn: expireTime,
    },
  );

  req.token = token;
  return next();
};

const validateAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  jwt.verify(token, secret, (e, decoded) => {
    if (e) {
      return res.status(403).json({ error: 'invalid token' });
    }
    req.emailAuth = decoded.email;
    return next();
  });
};

const permission = (req, res, next) => {
  const { uuid } = req.params;
  const { emailAuth } = req;
  const user = users.find((item) => item.uuid === uuid);

  if (!user) {
    return res.status(404).json({ error: 'user not found' });
  }
  if (user.email !== emailAuth) {
    return res
      .status(403)
      .json({ error: 'unauthorazed, you can only change your password' });
  }
  req.user = user;
  return next();
};

const checkPassword = async (req, res, next) => {
  const user = users.find((item) => item.email === req.body.email);
  const passwordMatch = await bcrypt.compare(req.body.password, user.password);
  if (!passwordMatch) {
    return res.status(400).json({ message: 'Invalid password' });
  }
  return next();
};

app.post('/signup', validateShape(userShape), async (req, res) => {
  const newUser = { ...req.valid };
  const userWithoutPassword = JSON.parse(JSON.stringify(newUser));
  delete userWithoutPassword.password;

  const hash = await bcrypt.hash(newUser.password, 10);
  newUser.password = hash;

  if (users.find((item) => item.email === newUser.email)) {
    return res.status(409).json({ error: 'email already exists' });
  }

  if (users.find((item) => item.username === newUser.username)) {
    return res.status(409).json({ error: 'username already exists' });
  }
  users.push(newUser);

  return res.status(201).json(userWithoutPassword);
});

app.post(
  '/login',
  validateShape(loginShape),
  checkLoginData,
  tokenGenerator,
  checkPassword,
  async (req, res) => {
    const { token } = req;

    return res.status(200).json({ accessToken: token });
  },
);

app.put(
  '/users/:uuid/password',
  validateShape(updatePasswordShape),
  validateAuth,
  permission,
  async (req, res) => {
    const { user } = req;
    const hash = await bcrypt.hash(user.password, 10);
    user.password = hash;
    res.status(204).json({ message: req.body });
  },
);

app.get('/users', validateAuth, (req, res) => {
  const allUsers = users;
  return res.status(200).json(allUsers);
});

app.listen(port, () => {
  console.log(`Running on http://localhost:${port}/ (Press CTRL+C to quit)`);
});
