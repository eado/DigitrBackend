console.log("Starting Digitr server...")

import WebSocket from 'ws';
import https from 'https';
import http from 'http'
import fs from 'fs';
import responder from './responder';
import { MongoClient } from 'mongodb';

// execSync("mongod --dbpath /var/data/db &")

const client = new MongoClient("mongodb://localhost:3232")

const config = JSON.parse(fs.readFileSync("config.json").toString())

// const server = https.createServer({
//     cert: fs.readFileSync(config.cert),
//     key: fs.readFileSync(config.key)
// })

const server = http.createServer({}, (_, res) => {res.end("hello")})

const wss = new WebSocket.Server({server})

wss.on('connection', function connection(ws) {
    (ws as any).isAlive = true;
    ws.on('pong', () => {(this as any).isAlive = true});

    ws.on('message', function incoming(message) {
        responder(JSON.parse((message as string)), ws, client.db("digitr"))
    })
});

// Alive listener
setInterval(function ping() {
wss.clients.forEach(function each(ws) {
    if ((ws as any).isAlive === false) return ws.terminate();

    (ws as any).isAlive = false;
    ws.ping(() => {(ws as any).isAlive = true;});
});
}, 30000);

client.connect(() => {
    server.listen(9001)

    // Index creation
    const db = client.db("digitr");
    const users = db.collection("users")
    const districts = db.collection("districts")

    setInterval(() => {
      const now = (Date.now() / 1000)
      users.find({}, {projection: {history: true}}).forEach(user => {
        const history: any[] = user.history ? user.history : []
        history.forEach(hist => {
          if (hist.timestamp_end) {
            return
          } else {
            if ((now - hist.timestamp) >= 84600) {
              hist.timestamp_end = hist.timestamp + 3600
              users.updateOne({email: user.email, 'history.timestamp': hist.timestamp}, {'$set': {'history.$.timestamp_end': hist.timestamp + 3600}})
            }
          }
        })
      })
    }, 3600 * 1000)

    setInterval(() => {
      const now = (Date.now() / 1000)
      districts.find({}, {projection: {teachers: false, students: false}}).forEach(district => {
        if (district.trial_start && !district.trial_finished) {
          const days = Math.floor((now - district.trial_start) / 86400)
          if (days > 30) {
            districts.updateOne({'domains': district.domains}, {'$set': {'trial_finished': true}})
            districts.updateOne({'domains': district.domains}, {'$set': {'analytics': false}})
          }
        }

        if (district.analytics_start_timestamp) {
          const days = Math.floor((now - district.analytics_start_timestamp) / 86400)
          if (days > 365) {
            districts.updateOne({'domains': district.domains}, {'$set': {'analytics': false}})
          }
        }

        const count = users.count({'domain': {'$in': district.domains}, 'is_teacher': false})
        if (district.max_count) {
          if (district.max_count < count)
            districts.updateOne({'domains': district.domains}, {'$set': {'max_count': count}})
        } else {
          districts.updateOne({'domains': district.domains}, {'$set': {'max_count': count}})
        }
      })
    }, 3600 * 1000)

    users.createIndex({'email': 1}, {unique: true})

    console.log("Secure WebSocket server listening on port 9001...")
})