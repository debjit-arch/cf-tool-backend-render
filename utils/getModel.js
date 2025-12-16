module.exports = function getModel(conn, name, schema) {
  return conn.models[name] || conn.model(name, schema);
};
