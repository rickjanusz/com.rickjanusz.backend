const { forwardTo } = require('prisma-binding')

const Query = {
  item: forwardTo('db'),

  async items(parent, args, ctx, info) {
    const items = await ctx.db.query.items()
    return items
  },

  // async item(parent, args, ctx, info) {
  //     const items = await ctx.db.query.items();
  //     return items
  // }
}

module.exports = Query
