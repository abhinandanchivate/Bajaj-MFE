Integrating **three Angular 19 microfrontends** and **two React microfrontends** into a single application can be achieved using **Module Federation**, which is the most popular and efficient way to implement microfrontends with Webpack. Here's a step-by-step guide to achieving this integration:

---

### **Step 1: Install Necessary Dependencies**
Ensure all your projects (Angular and React) have the required Webpack dependencies for module federation.

For Angular projects:

```sh
ng add @angular-architects/module-federation
```

For React projects:

```sh
npm install webpack webpack-cli webpack-dev-server webpack-merge html-webpack-plugin @module-federation/webpack-module-federation-plugin
```

---

### **Step 2: Configure Module Federation for Angular Microfrontends**

Each Angular microfrontend should have a `webpack.config.js` like:

#### `webpack.config.js` (Angular Microfrontend)
```js
const { shareAll, withModuleFederationPlugin } = require('@angular-architects/module-federation/webpack');

module.exports = withModuleFederationPlugin({
  name: 'angularMicrofrontend1',
  filename: 'remoteEntry.js',
  exposes: {
    './Component': './src/app/microfrontend.component.ts',
  },
  shared: shareAll({ singleton: true, strictVersion: false, requiredVersion: 'auto' }),
});
```

#### Update `angular.json`
Modify the `builder` property for your project to use `custom-webpack`:

```json
"architect": {
  "build": {
    "builder": "@angular-architects/module-federation:webpack",
    "options": {
      "outputPath": "dist/microfrontend1"
    }
  }
}
```

---

### **Step 3: Configure Module Federation for React Microfrontends**

Each React microfrontend should have a `webpack.config.js` like:

#### `webpack.config.js` (React Microfrontend)
```js
const ModuleFederationPlugin = require('webpack').container.ModuleFederationPlugin;

module.exports = {
  entry: './src/index',
  output: {
    publicPath: 'http://localhost:3002/',
  },
  mode: 'development',
  devServer: {
    port: 3002,
  },
  plugins: [
    new ModuleFederationPlugin({
      name: 'reactMicrofrontend1',
      filename: 'remoteEntry.js',
      exposes: {
        './Component': './src/components/MicrofrontendComponent',
      },
      shared: {
        react: { singleton: true, eager: true, requiredVersion: '^18.0.0' },
        'react-dom': { singleton: true, eager: true, requiredVersion: '^18.0.0' },
      },
    }),
  ],
};
```

---

### **Step 4: Set Up the Host Application**

The host application (could be Angular or React) should include all microfrontends dynamically.

#### `webpack.config.js` (Host Application)
```js
const ModuleFederationPlugin = require('webpack').container.ModuleFederationPlugin;

module.exports = {
  entry: './src/index',
  output: {
    publicPath: 'http://localhost:4200/',
  },
  mode: 'development',
  devServer: {
    port: 4200,
  },
  plugins: [
    new ModuleFederationPlugin({
      name: 'hostApp',
      remotes: {
        angularMicrofrontend1: 'angularMicrofrontend1@http://localhost:4201/remoteEntry.js',
        angularMicrofrontend2: 'angularMicrofrontend2@http://localhost:4202/remoteEntry.js',
        angularMicrofrontend3: 'angularMicrofrontend3@http://localhost:4203/remoteEntry.js',
        reactMicrofrontend1: 'reactMicrofrontend1@http://localhost:3002/remoteEntry.js',
        reactMicrofrontend2: 'reactMicrofrontend2@http://localhost:3003/remoteEntry.js',
      },
      shared: {
        react: { singleton: true, eager: true, requiredVersion: '^18.0.0' },
        'react-dom': { singleton: true, eager: true, requiredVersion: '^18.0.0' },
      },
    }),
  ],
};
```

---

### **Step 5: Load Microfrontends in Angular Host**

In the `app.routes.ts` of the Angular host application:

```typescript
const routes: Routes = [
  {
    path: 'angular-mf1',
    loadChildren: () =>
      import('angularMicrofrontend1/Component').then((m) => m.MicrofrontendComponent),
  },
  {
    path: 'react-mf1',
    component: ReactWrapperComponent, // Custom Angular wrapper for React
  },
];
```

To dynamically load React components in Angular:

```typescript
import React from 'react';
import ReactDOM from 'react-dom';
import { useEffect } from 'react';

const ReactComponent = React.lazy(() => import('reactMicrofrontend1/Component'));

export function ReactWrapperComponent() {
  useEffect(() => {
    ReactDOM.render(<ReactComponent />, document.getElementById('react-root'));
  }, []);

  return <div id="react-root"></div>;
}
```

---

### **Step 6: Load Angular Components in React Host**

To load Angular microfrontend in a React app:

```jsx
import React, { useEffect } from 'react';

const AngularMicrofrontend = React.lazy(() =>
  import('angularMicrofrontend1/Component')
);

const App = () => {
  useEffect(() => {
    const script = document.createElement('script');
    script.src = 'http://localhost:4201/main.js';
    document.body.appendChild(script);
  }, []);

  return (
    <div>
      <React.Suspense fallback={<div>Loading...</div>}>
        <AngularMicrofrontend />
      </React.Suspense>
    </div>
  );
};

export default App;
```

---

### **Step 7: Start Applications**

Run each microfrontend and host application on different ports:

```sh
ng serve --port 4201  # Angular Microfrontend 1
ng serve --port 4202  # Angular Microfrontend 2
ng serve --port 4203  # Angular Microfrontend 3
npm start -- --port 3002  # React Microfrontend 1
npm start -- --port 3003  # React Microfrontend 2
ng serve --port 4200  # Host Application
```

---

### **Step 8: Handling Routing Across Microfrontends**

Use **Angular Router** and **React Router** to manage navigation between microfrontends.

- Ensure routes are properly prefixed in `angular.json` for deployments.
- Use `basename` in React Router to avoid conflicts in routing.

---

### **Step 9: CI/CD and Deployment Considerations**

When deploying:

- Ensure the microfrontends are deployed to a CDN or cloud storage.
- Update the `remoteEntry.js` URLs dynamically using environment variables.
- Implement fallback strategies for microfrontends in case they are not available.

---

### **Conclusion**

By following the steps above, you can successfully integrate:

1. **3 Angular 19 microfrontends** using `@angular-architects/module-federation`.
2. **2 React microfrontends** using `@module-federation/webpack-module-federation-plugin`.
3. **A common host** (Angular/React) that dynamically loads the microfrontends.

Would you like further details on deployment strategies or routing management?
