// Importação de bibliotecas necessárias
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
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


// Configuração do serviço de e-mail
const transporter = nodemailer.createTransport({
    service: 'gmail', // Ou outro serviço como Outlook, Yahoo
    auth: {
      user: 'nathaliademacedomartins04@gmail.com', // Substitua pelo seu e-mail
      pass: 'mqsk gqxy ihoq evno', // Substitua pela senha do seu e-mail (ou App Password)
    },
  });


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
 *                 description: Email do usuário
 *               password:
 *                 type: string
 *                 description: Senha do usuário
 *     responses:
 *       200:
 *         description: Login realizado com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: Token JWT gerado para autenticação
 *                 name:
 *                   type: string
 *                   description: Nome do usuário logado
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
      res.status(200).json({ token, name: user.name });
    } catch (error) {
      res.status(500).json({ error: 'Algo deu errado' });
    }
  });

// Rota: Solicitar redefinição de senha
/**
 * @swagger
 * /forgot-password:
 *   post:
 *     summary: Solicitar a redefinição de senha
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: Email do usuário para enviar o código de redefinição
 *     responses:
 *       200:
 *         description: Código de redefinição enviado para o email
 *       404:
 *         description: Usuário não encontrado
 *       500:
 *         description: Erro ao solicitar redefinição de senha
 */
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
  
    try {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) {
        return res.status(404).json({ error: 'Usuário não encontrado' });
      }
  
      // Gerar um código de 6 dígitos aleatório
      const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
  
      // Atualizar o código no banco de dados
      await prisma.user.update({
        where: { email },
        data: { resetCode },
      });
  
      // Enviar o código para o e-mail do usuário
      await transporter.sendMail({
        from: 'seuemail@gmail.com', // Substitua pelo seu e-mail
        to: email,
        subject: 'Redefinição de senha Integral Energia',
        text: `Seu código de redefinição de senha é: ${resetCode}`,
      });
  
      res.status(200).json({ message: 'Código enviado para o e-mail' });
    } catch (error) {
      console.error('Erro ao enviar o e-mail:', error);
      res.status(500).json({ error: 'Erro ao solicitar redefinição de senha' });
    }
  });
  

// Rota: Redefinir senha
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
 *               email:
 *                 type: string
 *                 description: Email do usuário
 *               resetCode:
 *                 type: string
 *                 description: Código de 6 dígitos enviado por e-mail
 *               newPassword:
 *                 type: string
 *                 description: Nova senha do usuário
 *     responses:
 *       200:
 *         description: Senha redefinida com sucesso
 *       400:
 *         description: Código inválido ou expirado
 *       500:
 *         description: Erro ao redefinir senha
 */
app.post('/reset-password', async (req, res) => {
    const { email, resetCode, newPassword } = req.body;
  
    try {
      console.log('Requisição recebida:', { email, resetCode, newPassword });
  
      const user = await prisma.user.findUnique({ where: { email } });
      console.log('Usuário encontrado:', user);
  
      if (!user || user.resetCode !== resetCode) {
        return res.status(400).json({ error: 'Código inválido ou expirado' });
      }
  
      // Atualizar a senha e limpar o código de redefinição
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      console.log('Hash da nova senha:', hashedPassword);

      await prisma.user.update({
        where: { email },
        data: {
          password: hashedPassword,
          resetCode: null,
        },
      });
      
  
      console.log('Senha redefinida com sucesso para:', email);
      res.status(200).json({ message: 'Senha redefinida com sucesso' });
    } catch (error) {
      console.error('Erro ao redefinir senha:', error);
      res.status(500).json({ error: 'Erro ao redefinir senha' });
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
