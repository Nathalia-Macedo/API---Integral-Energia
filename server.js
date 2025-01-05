// Importação de bibliotecas necessárias
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const swaggerUi = require('swagger-ui-express');
const swaggerJsDoc = require('swagger-jsdoc');
require('dotenv').config();

const app = express();
const prisma = new PrismaClient({
    log: ['query', 'info', 'warn', 'error'], // Adiciona logs detalhados
  });
  const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Middleware
app.use(express.json());
app.use(cors());


// Configuração do Swagger
const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Autenticação',
      version: '1.0.0',
      description: 'API para autenticação de usuários',
    },
  },
  apis: ['./server.js'],
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Definição do schema Prisma
// Salve este schema no arquivo `prisma/schema.prisma`
/*
model User {
  id       String  @id @default(auto())
  email    String  @unique
  password String
  name     String
  resetToken String?
}
*/

// Rota: Cadastro de Usuário
/**
 * @swagger
 * /register:
 *   post:
 *     summary: Registrar um novo usuário
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *     responses:
 *       201:
 *         description: Usuário registrado com sucesso
 *       400:
 *         description: Usuário já existe
 */
app.post('/register', async (req, res) => {
  const { email, password, name } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, name },
    });
    res.status(201).json({ message: 'Usuário registrado com sucesso', user });
  } catch (error) {
    res.status(400).json({ error: 'Usuário já existe' });
  }
});

// Rota: Login de Usuário
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Fazer login do usuário
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login realizado com sucesso
 *       401:
 *         description: Credenciais inválidas
 */
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Algo deu errado' });
  }
});

// Rota: Esqueceu a Senha
/**
 * @swagger
 * /forgot-password:
 *   post:
 *     summary: Iniciar o processo de redefinição de senha
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: Email para redefinição enviado
 *       404:
 *         description: Usuário não encontrado
 */
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    const resetToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '15m' });
    await prisma.user.update({ where: { email }, data: { resetToken } });
    res.status(200).json({ message: 'Email para redefinição enviado', resetToken });
  } catch (error) {
    res.status(500).json({ error: 'Algo deu errado' });
  }
});


/**
 * @swagger
 * /reset-password:
 *   post:
 *     summary: Redefinir a senha do usuário
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               resetToken:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Senha redefinida com sucesso
 *       400:
 *         description: Token inválido ou expirado
 */
app.post('/reset-password', async (req, res) => {
    const { resetToken, newPassword } = req.body;
    try {
      const decoded = jwt.verify(resetToken, JWT_SECRET);
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await prisma.user.update({
        where: { id: decoded.userId },
        data: { password: hashedPassword, resetToken: null },
      });
      res.status(200).json({ message: 'Senha redefinida com sucesso' });
    } catch (error) {
      res.status(400).json({ error: 'Token inválido ou expirado' });
    }
  });
  


  // Rota: Listar Usuários
/**
 * @swagger
 * /users:
 *   get:
 *     summary: Obter todos os usuários cadastrados
 *     responses:
 *       200:
 *         description: Lista de usuários
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                   email:
 *                     type: string
 *                   name:
 *                     type: string
 */
app.get('/users', async (req, res) => {
    try {
      const users = await prisma.user.findMany({
        select: {
          id: true,
          email: true,
          name: true,
        },
      });
      res.status(200).header('Content-Type', 'application/json').json(users);
    } catch (error) {
      res.status(500).header('Content-Type', 'application/json').json({ error: 'Erro ao buscar usuários' });
    }
  });
  

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
  console.log(`Documentação Swagger disponível em http://localhost:${PORT}/api-docs`);
});
