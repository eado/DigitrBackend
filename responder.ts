import WebSocket from 'ws';
import { Db } from 'mongodb';
import request from 'request';
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import { createTransport } from 'nodemailer';
import { strings } from './strings';
import moment from 'moment';

const config = JSON.parse(fs.readFileSync("config.json").toString())

const gClient = new OAuth2Client(config.CLIENT_ID)

interface IData {
    [ key: string ]: () => void;
}

interface SNumber {
    [ name: string ]: number
}

export const uuidv4 = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0, v = c === 'x' ? r : ((r & 0x3) | 0x8);
        return v.toString(16);
    });
}

const pick = (o: any, ...fields: any[]) => {
    return fields.reduce((a, x) => {
        if(o.hasOwnProperty(x)) a[x] = o[x];
        return a;
    }, {});
}

const sendMail = (to: string, subject: string, text: string) => {
    const trans = createTransport({
        host: config.mailHost,
        port: config.mailPort,
        secure: true
    }, {auth: {user: config.mailUsername, pass: config.mailPassword}})

    trans.sendMail({
        from: config.mailUsername,
        to,
        subject,
        text
    })
}

export default async (message: any, ws: WebSocket, db: Db) => {
    console.log(message.email ? message.email: null)
    console.log(message)
    const send = (m: any) => {
        m.response_id = message.request_id
        console.log(message.email ? message.email: null)
        console.log(m)
        ws.send(JSON.stringify(m))
    }
    const sendSuccess = (m = {}) => send({success: true, ...m})
    const funSendSuccess = () => sendSuccess()
    const sendError = (errmsg: string) => send({error: errmsg})
    const funSendError = (errmsg: string) => (e: any) => {sendError(errmsg); console.log(e)}
    const sendWrapArray = (items: any[]) => send({items})

    const users = db.collection("users")
    const districts = db.collection("districts")

    const msUserExists = () => new Promise<any>((res, _) => {
        request.get("https://graph.microsoft.com/v1.0/me", {headers: {'Authorization': message.token}, json: true}, (err, _, body) => {
            if (err || !body.value) {
                res({user_exists: false})
                return
            }

            const jsonresp = body.value
            users.findOne({email: jsonresp.userPrincipalName}).catch(() => res({user_exists: false})).then((user) => {
                if (user) {
                    jsonresp.user_exists = true
                    jsonresp.is_teacher = user.is_teacher
                    res(jsonresp)
                }
            }, () => res({user_exists: false}))
        })
    })

    const verifyUser = async () => {
        if (message.ms) {
            return ((await msUserExists()).user_exists as boolean)
        }

        return (await gVerify()) === message.email
    }

    const gVerify = async () => {
        try {
            const ticket = await gClient.verifyIdToken({idToken: message.token, audience: [config.CLIENT_ID, config.CLIENT_ID_2]})

            const payload = ticket.getPayload()
            return payload ? payload.email : null
        } catch {
            return null
        }
    }

    const isAdmin = async ()  => {
        const user = await users.findOne({email: message.email})
        const district = await districts.findOne({domains: message.email.split('@')[1]})
        if (!district || !user) { sendError('cof'); return }
        if (district.admins.map((a: string) => a.toLowerCase()).indexOf(user.email) > -1) {
            return true
        } else {
            return false
        }
    }

    const sendMessage = (message: any, emails: string[]) => {
        emails.forEach(email => {
            users.updateOne({email}, {'$push': {messages: message}})
        })
    }

    const getStats = async (admin: boolean) => {
        const stater = await users.findOne({email: message.email})
        if (!stater) { sendError('cof'); return }
        const district = await districts.findOne({domains: stater.domain})
        if (!district) { sendError('cof'); return }

        const mess = {passesIssued: 0, avgInterval: strings.intervalDefault, avgMinutes: 0, freePasses: 0, regularPasses: 0, mvp: strings.mvpDefault, currentlyOut: [] as any[], mvt: strings.mvpDefault, mud: strings.mudDefault}
        let counts: SNumber = {}
        let teacherCounts: SNumber = {}
        let destCounts: SNumber = {}
        let intervals = []
        let minutesTotal = 0
        const usersRef = users.find({domain: {$in: district.domains}}, {projection: {history: true, name: true}}).toArray()
        for (const user of await usersRef) {
            counts[user.name] = 0
            for (const pass of user.history) {
                pass.user = user.name
                if ((admin || pass.teacher === stater.name || (message.all && district.out_teachers)) && !pass.timestamp_end) {
                    mess.currentlyOut.push(user.name)
                }
                mess.passesIssued++
                if (pass.name === "Free") mess.freePasses++ 
                else mess.regularPasses++
                counts[user.name]++
                if (!destCounts[pass.destination]) destCounts[pass.destination] = 0
                destCounts[pass.destination]++
                if (admin) {
                    if (!teacherCounts[pass.teacher]) teacherCounts[pass.teacher] = 0
                    teacherCounts[pass.teacher]++
                }
                if (pass.timestamp_end) intervals.push((pass.timestamp_end ? pass.timestamp_end : pass.timestamp) - pass.timestamp)
                minutesTotal += pass.minutes
            }
        }

        if (mess.passesIssued < 1) { send(mess); return }

        mess.avgMinutes = Math.round(minutesTotal / mess.passesIssued)
        const max = (object: any) => {
            return Object.keys(object).filter(x => {
                 return object[x] == Math.max.apply(null, 
                 Object.values(object));
           })[0];
        };
        mess.mvp = max(counts)
        if (admin) mess.mvt = max(teacherCounts)
        mess.mud = max(destCounts)

        if (intervals.length > 2) {
            const interval = intervals[Math.round(intervals.length / 2)]
            mess.avgInterval = strings.interval.format(String(Math.round(interval / 60)), String(Math.round(interval) % 60))
        }
        send(mess)
    }

    const getCSV = async (admin: boolean) => {
        const stater = await users.findOne({email: message.user ? message.user : message.email})
        if (!stater) { sendError('cof'); return }
        const district = await districts.findOne({domains: stater.domain})
        if (!district) { sendError('cof'); return }

        const query: any = {domain: {$in: district.domains}}
        if (!admin || (stater.is_teacher && message.user)) {
            query['history.teacher'] = stater.name
        } else if (!stater.is_teacher) {
            query['email'] = stater['email']
        }

        const usersRef = users.find(query, {projection: {history: true, name: true}}).toArray()
        let csvText = strings.csvStartingText

        let fromDate, toDate, fromTime, toTime
        if (message.fromDate) fromDate = moment(message.fromDate, "YYYY-MM-DD")
        if (message.toDate) toDate = moment(message.toDate, "YYYY-MM-DD")
        if (message.fromTime) fromTime = moment(message.fromTime, "HH:mm")
        if (message.toTime) toTime = moment(message.toTime, "HH:mm")

        const addCol = (...data: string[]) => csvText = csvText.concat(data.join(",").concat(","))
        const addRow = () => csvText = csvText.concat("\n")

        for (const user of await usersRef) {
            for (const pass of user.history) {
                if ((!admin || (stater.is_teacher && message.user)) && pass.teacher !== stater.name) continue

                const datetime = moment.unix(pass.timestamp)
                const time = moment(datetime.format("HH:mm"), "HH:mm")
                if (fromDate && datetime < fromDate) continue
                if (toDate && datetime > toDate) continue
                if (fromTime && time < fromTime) continue
                if (toTime && time > toTime) continue
                if (message.dest && pass.destination !== message.dest) continue

                addCol(user.name, String(pass.name), pass.destination, pass.teacher, String(pass.minutes))
                addCol(datetime.format("YYYY-MM-DD HH:mm:ss"))
                addCol(moment.unix(pass.timestamp_end ? pass.timestamp_end : pass.timestamp).format("YYYY-MM-DD HH:mm:ss"))
                addRow()
            }
        }
        send({csv_data: csvText})
    }

    const approvePass = async () => {
        const district = await districts.findOne({domains: message.email.split('@')[1]})
        if (!district) {sendError('cof'); return}
        const legacy = district.legacy
        const teacher = await users.findOne({email: legacy ? message.user : message.email})
        const user = await users.findOne({email: legacy ? message.email : message.user})
        if (!user || !district || !teacher) { sendError('cof'); return }

        const name = message.free ? 'Free' : Number(district.pass) - (user.history as any[]).filter(h => h.name !== "Free").length
        
        const timestamp = Date.now() / 1000

        const minutes = legacy ? 5 : message.minutes;
        const destination = legacy ? message.dest : message.destination;
        users.updateOne({email: legacy ? message.email : message.user}, {$push: {history: {
            destination,
            teacher: teacher.name,
            timestamp,
            minutes,
            name
        }}})

        const mess: any = {
            user: teacher.name,
            email: teacher.email,
            type: 'pass_approved',
            title: strings.passApproved,
            subTitle: strings.passApprovedText.format(destination, minutes),
            timestamp,
            minutes,
            name
        }
        sendMessage(mess, [legacy ? message.email : message.user])
        sendSuccess()

        setTimeout(async() => {
            const user = await users.findOne({email: legacy ? message.email : message.user})
            if (!user) { sendError('cof'); return }
            if ((user.history as any[]).find(h => h.timestamp === timestamp && h.timestamp_end)) {
                return
            }

            const time = Date.now() / 1000
            const mess1: any = {
                user: teacher.name,
                email: teacher.email,
                type: 'pass_done',
                title: strings.passDone,
                subTitle: strings.passDoneTextStudent,
                timestamp: time,
                pass_time: timestamp,
                minutes,
                name
            }
            sendMessage(mess1, [legacy ? message.email : message.user])

            const mess2: any = {
                user: user.name,
                email: user.email,
                type: 'pass_done',
                title: strings.passDone,
                subTitle: strings.passDoneTextTeacher.format(user.name),
                timestamp: time,
                pass_time: timestamp,
                minutes,
                name
            }
            sendMessage(mess2, [legacy ? message.user : message.email])
        }, minutes * 60 * 1000)
    }
    
    const functions: IData = {
        get_ms_data: async () => send(await msUserExists()),
        get_district: () => districts.findOne({'domains': message.domain}).then(district => {
            if (!district) { sendError('cof'); return }
            send({exists: true, schools: district.schools, teachers_enabled: district.teachers_enabled})
        }, () => send({exists: false})).catch(() => send({exists: false})),
        user_exists: () => users.findOne({email: message.email}).then(u => {
            if (!u ) { sendError('cof'); return }
            sendSuccess({user_exists: true, is_teacher: u.is_teacher})
        }, () => sendSuccess({user_exists: false})).catch(() => sendSuccess({user_exists: false})),
        signin: async () => {
            const email = await gVerify()
            if (!email) {
                sendError('csu')
            }
            const userExists = (user_exists: boolean) => () => sendSuccess({user_exists})
            users.findOne({email}).then(userExists(true), userExists(false)).catch(userExists(false))
        }
    }

    const functionsWithVerify: IData = {
        get_district_info: async () => {
            const district = await districts.findOne({domains: message.domain})
            if (!district) { sendError('cof'); return }
            const teachers = await users.find({domain: {'$in': district.domains}, is_teacher: true})
            const teachers_with_names = (await teachers.toArray()).map(t => [t.email, t.name])

            send({...pick(district, "schools", "pass", "destinations", "admins", "analytics", "domains", "legacy", "teachers_enabled", "out_teachers", "limit_students"), teachers_with_names})
        },
        add_user: async () => {
            const school = message.school ? message.school : null
            const domain = message.email.split('@')[1]
            const district = await districts.findOne({domains: domain})

            if (!district) {
                sendError('dde')
                return
            }

            if (message.is_teacher && (("teachers_enabled" in district) && !district.teachers_enabled)) {
                sendError('tne')
                return
            }
            if (!message.is_teacher && district.limit_students) {
                if (district.limit_students.indexOf(message.email) < 0) {
                    sendError('nil')
                    return
                }
            }

            users.insertOne({name: message.name, email: message.email, is_teacher: message.is_teacher, school, domain, history: [], messages: [], notifications: []})

            if (message.is_teacher) {
                districts.updateOne({domains: domain}, {'$push': {teachers: message.email}})
            } else {
                districts.updateOne({domains: domain}, {'$push': {students: message.email}})
            }

            sendSuccess()
        },
        add_district: () => {
            const schools = message.schools ? message.schools : null
            districts.insertOne({domains: message.domains, pass: message.pass, schools: schools, admins: [message.email], legacy: false, teachers_enabled: true, out_teachers: false})
            sendSuccess()
            sendMail(config.mailUsername, strings.signedUpEmailSubject, strings.signedUpEmailText.format(message.email, message.schoolname))
        },
        get_user: async () => {
            const currentUser = await users.findOne({email: message.email})
            if (!currentUser) { sendError('cof'); return }
            const userIsUser = message.email === message.user
            let user = userIsUser ? currentUser : await users.findOne({email: message.user})
            if (!user) {sendError("cof"); return}
            user._id = null

            if (currentUser.is_teacher || userIsUser) {
                sendSuccess({user})
                if (message.once) {return}
                const int = setInterval(async () => {
                    console.log(message.email)
                    if (ws.readyState !== ws.OPEN) {
                        clearInterval(int)
                    }
                    let newUser = await users.findOne({email: message.user})
                    if (!newUser || !user) {return}
                    const newUserTimestamp = Math.max(...newUser.messages.map((m: any) => m.timestamp))
                    const userTimestamp = Math.max(...user.messages.map((m: any) => m.timestamp))
                    if ((newUserTimestamp !== userTimestamp) || newUser.history.length != user.history.length) {
                        user = newUser
                        user._id = null
                        sendSuccess({user})
                    }
                }, 2000)
            } else {
                sendError('unu')
            }
        },
        get_user_from_name: async () => {
            const currentUser = await users.findOne({email: message.email})
            if (!currentUser) { sendError('cof'); return }
            const user = await users.findOne({name: message.user})

            if (currentUser.is_teacher) {
                sendSuccess({user})
            }
        },
        request_pass: async () => {
            const user = await users.findOne({email: message.email})
            const teacher = await users.findOne({email: message.user})
            const domain = message.email.split("@")[1]
            const district = await districts.findOne({domains: domain})
            if (!district || !teacher || !user) { sendError('cof'); return }

            const passesLeft = Number(district.pass) - (user.history as any[]).filter(h => h.name !== "Free").length
            const passesByTeacher = (user.history as any[]).filter(h => (h.name !== "Free") && (h.teacher === teacher.name)).length

            const mess: any = {
                user: user.name,
                email: message.email,
                destination: message.dest,
                timestamp: Date.now() / 1000,
                pass: passesLeft
            }

            if (district.legacy) {
                if (passesLeft > 0) {
                    approvePass()
                    mess.type = "custom",
                    mess.title = strings.passUsed,
                    mess.subTitle = strings.passUsedText.format(user.name, message.dest, String(passesLeft), String(passesByTeacher))
                    sendMessage(mess, [message.user])
                } else {
                    sendError('nnp')
                }
                return
            }

            mess.type = "pass_request"
            mess.title = strings.passRequest
            mess.subTitle = strings.passRequestText.format(user.name, message.dest, String(passesLeft), String(passesByTeacher))
            sendMessage(mess, [message.user])
            sendSuccess()
        },
        deny_pass: async () => {
            users.updateOne({email: message.email}, {'$pull': {messages: {'timestamp': message.message_time}}})
            const user = await users.findOne({email: message.email})
            if (!user) { sendError('cof'); return }

            const mess = {
                user: user.name,
                email: message.email,
                type: "pass_rejected",
                title: strings.passRejected,
                subTitle: strings.passRejectedText,
                timestamp: Date.now() / 1000
            }
            sendMessage(mess, [message.user])
            sendSuccess()
        },
        dismiss_message: () => {
            users.updateOne({'email': message.email}, {'$pull': {'messages': {'timestamp': message.message_time}}})
            sendSuccess()
        },
        approve_pass: () => approvePass(),
        back_from_pass: async () => {
            const user = await users.findOne({email: message.email})
            if (!user) { sendError('cof'); return }
            if ((user.history as any[]).find(h => h.timestamp === message.timestamp && h.timestamp_end)) {
                sendError('arb')
                return
            }

            const timestamp = Date.now() / 1000
            users.updateOne({'email': message.email, 'history.timestamp': message.timestamp}, 
                                 {'$set': {'history.$.timestamp_end': timestamp}})

            sendMessage({
                user: user.name,
                email: user.email,
                type: 'pass_done',
                title: strings.passBack,
                subTitle: strings.passBackText.format(user.name),
                timestamp
            }, [message.teacher])
            sendSuccess()
        },
        get_teacher_users: async () => {
            const user = await users.findOne({'email': message.email})
            if (!user ) { sendError('cof'); return }
            const district = await districts.findOne({'domains': user.domain})
            if (!district ) { sendError('cof'); return }
            if (!user.is_teacher) {
                sendError('unt')
                return
            }
            send({users: await users.distinct("name", {is_teacher: false, domain: {$in: district.domains}, "history.teacher": user.name})})
        },
        clear_messages: () => {
            users.updateOne({email: message.email}, {$set: {messages: []}})
            sendSuccess()
        },
        send_everyone_back: async () => {
            const user = await users.findOne({'email': message.email})
            if (!user ) { sendError('cof'); return }
            const district = await districts.findOne({'domains': user.domain})
            if (!district ) { sendError('cof'); return }

            users.updateMany({domain: {$in: district.domains}}, 
                {$set: {'history.$[element].timestamp_end': Date.now() / 1000}}, 
                {upsert: false, arrayFilters: [{$and: [{"element.teacher": user.name}, {"element.timestamp_end": null}]}]})
            sendSuccess()
        },
        send_back: async () => {
            const user = await users.findOne({email: message.email})
            if (!user ) { sendError('cof'); return }
            if (!user.is_teacher) {
                sendError('unt'); return
            }

            users.updateOne({'email': message.user, 'history.timestamp': message.timestamp}, 
                                 {'$set': {'history.$.timestamp_end': Date.now() / 1000}})
            sendSuccess()
        },
        get_teacher_stats: () => getStats(false),
        get_csv_for_teacher: () => getCSV(false),
        send_custom_message: async () => {
            const user = await users.findOne({email: message.email})
            if (!user ) { sendError('cof'); return }
            sendMessage({user: user.name, email: user.email, type: 'custom', title: user.name, subTitle: message.message, timestamp: Date.now() / 1000}, [message.user])
        },
    }

    const functionsWithAdmin: IData = {
        send_to_all: async () => {
            const user = await users.findOne({email: message.email})
            if (!user ) { sendError('cof'); return }
            const district = await districts.findOne({'domains': user.domain})
            if (!district ) { sendError('cof'); return }
            sendMessage({user: user.name, email: user.email, type: 'custom', title: user.name, subTitle: message.message, timestamp: Date.now() / 1000},
                district.students.concat(district.teachers))
        },
        get_csv_for_admin: async () => getCSV(true),
        get_admin_stats: async () => getStats(true),
        purge_pass: async () => {
            const user = await users.findOne({email: message.user})
            if (!user ) { sendError('cof'); return }
            const history = user.history.filter((h: any) => h.timestamp !== message.timestamp)
            users.updateOne({email: message.user}, {$set: {history}})
            sendSuccess()
        },
        set_timestamp: () => users.updateOne({email: message.user, 'history.timestamp': message.timestamp}, {$set: {'history.$.timestamp': message.timestamp}}).then(funSendSuccess, funSendError('cst')).catch(funSendError('cst')),
        get_admin_users: async () => {
            const district = await districts.findOne({domains: message.email.split('@')[1]})
            if (!district ) { sendError('cof'); return }
            send({users: await users.distinct("name", {domain: {$in: district.domains}, is_teacher: false})})
        },
        remove_user: async () => users.deleteOne({email: message.user}).then(funSendSuccess, funSendError('cdu')).catch(funSendError('cdu')),
        edit_district: async () => {
            const query = {domains: message.email.split('@')[1]}
            const district = await districts.findOne(query)
            if (!district ) { sendError('cof'); return }
            if (['admin', 'school', 'domain', 'dest'].find(f => f === message.field)) {
                const plural = message.field === 'dest' ? 'destinations' : message.field + "s"
                const method = message.type == "add" ? "$push": "$pull"
                if (district[plural]) districts.updateOne(query, {[method]: {[plural]: message.data}})
                else districts.updateOne(query, {$set: {[plural]: [message.data]}})
            } else if (['legacy', 'teachers_enabled', 'out_teachers', 'pass', 'limit_students']) {
                districts.updateOne(query, {$set: {[message.field]: message.data}})
            }
            sendSuccess()
        },
        reset_passes: async () => {
            const district = await districts.findOne({domains: message.email.split('@')[1]})
            if (!district ) { sendError('cof'); return }
            users.updateMany({domain: {$in: district.domains}}, {$set: {history: []}}).then(funSendSuccess, funSendError('crp')).catch(funSendError('crp'))
        },
        start_fresh: async () => {
            const district = await districts.findOne({domains: message.email.split('@')[1]})
            if (!district ) { sendError('cof'); return }
            users.deleteMany({'domain': {'$in': district.domains}, 'email': {'$not': {'$eq': message.email}}})
            district.teachers = [message.email]
            district.students = []
            districts.deleteOne({domains: district.domains[0]})
            districts.insertOne(district)
            sendSuccess()
        },
        get_payment_stats: async () => {
            const district = await districts.findOne({domains: message.email.split('@')[1]})
            if (!district ) { sendError('cof'); return }
            const count = await users.count({domain: {$in: district.domains}, is_teacher: false})
            send({count: count ? count : 0, trial_finished: district.trial_finished, trial_start: district.trial_start, start: district.analytics_start_timestamp, max_count: district.max_count ? district.max_count : 0, last_payment_count: district.last_payment_count})
        },
        start_trial: async () => {
            const district = await districts.findOne({domains: message.email.split('@')[1]})
            if (!district ) { sendError('cof'); return }
            if (!district.trial_finished) {
                districts.updateOne({domains: message.email.split('@')[1]}, {$set: {analytics: true, trial_start: Date.now() / 1000}})
            }
            sendSuccess()
        }
    }

    try {
        functions[message.request]()
    } catch (error) {
        try {
            if (await verifyUser()) {
                try {
                    functionsWithVerify[message.request]()
                } catch {
                    if (await isAdmin()) {
                        functionsWithAdmin[message.request]()
                    } else {
                        sendError('una')
                    }
                }
            } else {
                sendError('uns')
            }
        } catch {
            sendError('nvf')
        }
    }
}