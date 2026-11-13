/*
 * DEMO ONLY: a deliberately vulnerable endpoint, to show that the
 * DevSecOps pipeline blocks a NEW SQL injection. Never merge.
 */
import express, { type Request, type Response } from 'express'
import * as models from '../models/index'

const router = express.Router()

router.get('/rest/demo/search', async (req: Request, res: Response) => {
  const name = req.query.q
  // Vulnerable on purpose: user input is pasted into the SQL string
  const [rows] = await models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${name}%'`)
  res.json(rows)
})

export default router
