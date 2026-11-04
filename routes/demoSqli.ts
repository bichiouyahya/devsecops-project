import { type Request, type Response } from 'express'
import * as models from '../models/index'

export function demoSearch () {
  return (req: Request, res: Response) => {
    models.sequelize.query(`SELECT * FROM Products WHERE name = '${req.query.q}'`)
      .then(([rows]: any) => res.json(rows))
  }
}
