import webpack from 'webpack';
import path from 'path';

const name = 'OCIFnAuth';

const production = process.env.NODE_ENV === 'production';

const config = {
  target: 'node-webkit',
  entry: [
    'jsrsasign',
    './src/OciFnAuth.js'
  ],
  output:{
    path: path.join(__dirname, './build/me.harwell.PawExtensions.OciFnAuth'),
    pathinfo: true,
    publicPath: '/build/',
    filename: name + '.js'
  },
  module: {
    loaders: [
      {
        loader: 'babel-loader',
        include: [
          path.resolve(__dirname, 'src')
        ],
        test: /\.js$/
      }
    ]
  }
};

module.exports = config;
