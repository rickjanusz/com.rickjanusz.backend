const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { randomBytes } = require('crypto')
const { promisify } = require('util')
const { transport, makeANiceEmail } = require('../mail')
const { hasPermission } = require('../utils')

const Mutations = {
  async createItem(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that!')
    }
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          // This is how we create a relationship between the item and the user
          user: {
            connect: {
              id: ctx.request.userId,
            },
          },
          ...args,
        },
      },
      info
    )
    return item
  },
  updateItem(parent, args, ctx, info) {
    const updates = { ...args }
    delete updates.id
    return ctx.db.mutation.updateItem(
      {
        data: updates,
        where: {
          id: args.id,
        },
      },
      info
    )
  },
  async deleteItem(parent, args, ctx, info) {
    // throw new Error("You aren't allowed to do that!")

    const where = { id: args.id }
    // find the item
    const item = await ctx.db.query.item({ where }, `{ id title user { id }}`)
    // check to see if they have the permissions to do this.
    const ownsItem = item.user.id === ctx.request.userId
    const hasPermission = ctx.request.user.permissions.some(permission =>
      ['ADMIN', 'ITEMDELETE'].includes(permission)
    )

    if (!ownsItem && !hasPermission) {
      throw new Error("You don't have permission to do that!")
    }
    // delete the item
    return ctx.db.mutation.deleteItem({ where }, info)
  },
  async signup(parent, args, ctx, info) {
    args.email = args.email.toLowerCase()
    const password = await bcrypt.hash(args.password, 10)
    const user = await ctx.db.mutation.createUser(
      {
        data: {
          ...args,
          password,
          permissions: { set: ['USER'] },
        },
      },
      info
    )
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET)
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365,
    })
    return user
  },
  async signin(parent, { email, password }, ctx, info) {
    const user = await ctx.db.query.user({ where: { email } })
    if (!user) {
      throw new Error(`No such user found for email ${email}`)
    }

    const valid = await bcrypt.compare(password, user.password)
    if (!valid) {
      throw new Error('Invalid Password')
    }

    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET)
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365,
    })

    return user
  },
  signout(parent, args, ctx, info) {
    ctx.response.clearCookie('token')
    return { message: 'Goodbye!' }
  },
  async requestReset(parent, args, ctx, info) {
    const user = await ctx.db.query.user({ where: { email: args.email } })
    if (!user) {
      throw new Error(`No such user found for email ${args.email}`)
    }
    const randomBytesPromisified = promisify(randomBytes)
    const resetToken = (await randomBytesPromisified(28)).toString('hex')
    const resetTokenExpiry = Date.now() + 3600000
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry },
    })
    // 3. Email them the token
    const mailRes = await transport.sendMail({
      from: 'Rick Janusz',
      to: user.email,
      subject: 'Your Password Reset Token',
      html: makeANiceEmail(
        `Your password reset token is here: \n\n <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">Reset Your Password Now &gt;&gt;</a>"`
      ),
    })

    // 4. return message
    return { message: 'Thanks!' }
  },
  async resetPassword(parent, args, ctx, info) {
    // 1. Check to see if passwords match
    if (args.password !== args.confirmPassword) {
      throw new Error("Your passwords don't match")
    }
    // 2. Check to see if its a legit reset token
    // 3. Check to see if its expired
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 36000000,
      },
    })
    if (!user) {
      throw new Error('This password it either invalid or expired')
    }
    // 4. Hash new password
    const password = await bcrypt.hash(args.password, 10)
    // 5. Save the new password to the user and remove the old resetToken fields
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password,
        resetToken: null,
        resetTokenExpiry: null,
      },
    })
    // 6. Generate the jwt
    const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET)
    // 7. Set the jwt cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365,
    })
    // 8. return the new user
    return updatedUser
  },
  async updatePermissions(parent, args, ctx, info) {
    // 1. Check if they're logged in
    if (!ctx.request.user) {
      throw new Error('You must be logged in to do that')
    }
    // 2. Query the current user
    const currentUser = await ctx.db.query.user(
      {
        where: {
          id: ctx.request.userId,
        },
      },
      info
    )
    // 3. Check if they have the permissions to do this
    hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE'])
    // 4. Update the permissions
    return ctx.db.mutation.updateUser(
      {
        data: {
          permissions: {
            set: args.permissions,
          },
        },
        where: {
          id: args.userId,
        },
      },
      info
    )
  },
}

module.exports = Mutations
