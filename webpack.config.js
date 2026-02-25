const path = require('path');

const name = 'OCIFnAuth';

const config = {
  mode: 'production',
  target: 'node-webkit',
  entry: [
    'jsrsasign',
    './src/OciFnAuth.ts'
  ],
  output:{
    path: path.join(__dirname, 'build/me.harwell.PawExtensions.OciFnAuth'),
    pathinfo: true,
    publicPath: '/build/',
    filename: name + '.js'
  },
  resolve: {
    extensions: ['.ts', '.js']
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        include: [
          path.resolve(__dirname, 'src')
        ]
      }
    ]
  }
};

module.exports = config;
