const path = require('path');

const name = 'OCIFnAuth';

const config = {
  mode: 'production',
  target: 'node-webkit',
  entry: [
    'jsrsasign',
    './src/OciFnAuth.js'
  ],
  output:{
    path: path.join(__dirname, 'build/me.harwell.PawExtensions.OciFnAuth'),
    pathinfo: true,
    publicPath: '/build/',
    filename: name + '.js'
  },
  module: {
    rules: [
      {
        use: 'babel-loader',
        include: [
          path.resolve(__dirname, 'src')
        ],
        test: /\.js$/
      }
    ]
  }
};

module.exports = config;
