import dotenv from 'dotenv'
import connectDB from './db/index.js'
import { app } from './app.js'
dotenv.config({ path: './env' })

connectDB()
  .then(() => {
    app.on('error', (err) => {
      console.log('ERR', err)
      throw err
    })
    app.listen(process.env.PORT || 8000, () => {
      console.log(`server is running at port ${process.env.PORT}`)
    })
  })
  .catch((err) => {
    console.log('Mongo connection failed', err)
  })
