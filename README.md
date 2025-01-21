# Ecommerce App with Micro Frontends and NgRx Integration

## Table of Contents

1. **Introduction**
2. **Micro Frontend Architecture Overview**
3. **Technology Stack**
4. **Workflow and Integration Steps**
5. **Host and Micro Frontend Setup**
6. **NgRx State Management**
7. **Lazy Loading and Routing**
8. **Cross-App Communication**
9. **State Persistence**
10. **Testing Strategy**
11. **Deployment and Scaling**
12. **Best Practices**

---

## 1. Introduction

The Ecommerce App follows a **Micro Frontend Architecture**, allowing different business features (e.g., Product Catalog, Cart, Checkout) to be independently developed, deployed, and maintained. This approach enhances scalability, team autonomy, and allows for easier technology upgrades without affecting the entire application.

Micro frontends enable teams to work on smaller, decoupled codebases, making it easier to add new features and maintain existing ones. Each micro frontend in this application represents a business domain and operates independently while being integrated into a unified host shell application.

This architecture leverages Webpack Module Federation, which allows sharing dependencies and runtime module loading, thus optimizing performance and reducing redundancy. The NgRx state management library is used to ensure predictable data flow and synchronization across multiple micro frontends, providing features such as state persistence, actions, and side-effect management.

**Benefits of Micro Frontend Architecture:**

- **Independent Deployment:** Micro frontends can be deployed independently, reducing the risk of full application failure.
- **Scalability:** Enables horizontal scaling by distributing workloads across different teams.
- **Technology Flexibility:** Different micro frontends can adopt different frameworks or versions.
- **Improved Maintainability:** Easier debugging and enhancements due to smaller, focused codebases.
- **Team Autonomy:** Different teams can work on individual micro frontends with minimal dependencies.

**Key Features Implemented:**

- **Micro Frontend Modules:**
  - Product Catalog Micro Frontend
  - Cart Micro Frontend
  - Checkout Micro Frontend
- **Shared State Management with NgRx:**
  - Centralized state handling for user interactions.
  - Ensuring synchronization across micro frontends.
- **Lazy Loading and Dynamic Imports:**
  - Improved performance by loading micro frontends only when needed.
- **Authentication and Security:**
  - JWT-based authentication to securely manage user sessions across all micro frontends.
- **Continuous Integration and Deployment:**
  - Automated builds and deployments using Docker and Kubernetes.

---

## 2. Micro Frontend Architecture Overview

### **Architecture Components**

**Host Application (Shell):**
- Provides global layout, authentication, and routing.
- Dynamically loads micro frontends.
- Handles shared dependencies like styles, NgRx Store, and authentication tokens.

**Product Micro Frontend (MFE):**
- Responsible for product listing and detail views.
- Interacts with shared NgRx store for cart updates.

**Cart Micro Frontend (MFE):**
- Manages cart operations.
- Syncs cart data with the backend API.

**Checkout Micro Frontend (MFE):**
- Handles order placement and payment integration.
- Communicates with external payment gateways.

---

### **Detailed Component Diagram**
```
              +---------------------------------------------------+
               |                 Host Application (Shell)           |
               |  - Provides global layout & authentication         |
               |  - Dynamically loads micro frontends                |
               |  - Handles shared dependencies (NgRx, styles)       |
               +---------------------------------------------------+
                                   |
        -----------------------------------------------------------
        |                         |                              |
+---------------------+  +---------------------+  +---------------------+
|  Product MFE        |  |  Cart MFE            |  |  Checkout MFE         |
|  - Product listing  |  |  - Manage cart       |  |  - Handle payment     |
|  - Product details  |  |  - Sync with API     |  |  - External gateways  |
+---------------------+  +---------------------+  +---------------------+
```

---

## 3. Technology Stack

- **Frontend:** Angular 19
- **State Management:** NgRx Store, Effects
- **Micro Frontend Integration:** Webpack Module Federation
- **Backend:** Node.js, Express, PostgreSQL
- **Deployment:** Docker, Kubernetes
- **Authentication:** JWT, OAuth2

---

## 4. Workflow and Integration Steps

1. Set up Angular projects for host and micro frontends.
2. Configure Module Federation for dynamic loading.
3. Implement NgRx Store for state management.
4. Define communication strategies across MFEs.
5. Integrate authentication and authorization mechanisms.
6. Deploy using Docker containers.

---

## 5. Webpack Module Federation Setup

**Step 1: Install Dependencies**
```bash
npm install @angular-architects/module-federation --save
```

**Step 2: Configure Host Application**
```js
const { shareAll, withModuleFederationPlugin } = require('@angular-architects/module-federation/webpack');

module.exports = withModuleFederationPlugin({
  remotes: {
    product: "product@http://localhost:4201/remoteEntry.js",
    cart: "cart@http://localhost:4202/remoteEntry.js"
  },
  shared: shareAll({ singleton: true, strictVersion: false, requiredVersion: 'auto' })
});
```

**Step 3: Configure Micro Frontend Applications**
```js
module.exports = withModuleFederationPlugin({
  name: 'product',
  filename: 'remoteEntry.js',
  exposes: {
    './ProductModule': './src/app/product/product.module.ts',
  },
  shared: shareAll({ singleton: true, strictVersion: false, requiredVersion: 'auto' })
});
```

**Step 4: Load Micro Frontend Dynamically**
```ts
const routes: Routes = [
  { path: 'product', loadChildren: () => import('product/ProductModule').then(m => m.ProductModule) },
  { path: 'cart', loadChildren: () => import('cart/CartModule').then(m => m.CartModule) }
];
```

**Step 5: Running Applications**
```bash
ng serve --port 4200  # Host Application
ng serve --port 4201  # Product Micro Frontend
ng serve --port 4202  # Cart Micro Frontend
```



---

## NgRx State Management

NgRx is used to manage the application state across multiple micro frontends (MFEs), providing a predictable state management solution and ensuring consistency across different micro frontends.

### **Core Concepts of NgRx State Management for MFEs:**

1. **Actions:**
   - Define what kind of state changes can happen in different MFEs.
   - Each MFE defines its own set of actions while sharing some global actions.
   - Example:
   ```typescript
   export const addToCart = createAction('[Cart MFE] Add Item', props<{ product: Product }>());
   export const removeFromCart = createAction('[Cart MFE] Remove Item', props<{ productId: number }>());
   ```

2. **Reducers:**
   - Pure functions specifying how the state changes in response to actions within MFEs.
   - Example:
   ```typescript
   export const cartReducer = createReducer(
     initialState,
     on(addToCart, (state, { product }) => ({ ...state, items: [...state.items, product] })),
     on(removeFromCart, (state, { productId }) => ({
       ...state,
       items: state.items.filter(item => item.id !== productId)
     }))
   );
   ```

3. **Selectors:**
   - Functions to query and derive data from the state shared across MFEs.
   - Example:
   ```typescript
   export const selectCartItems = createSelector(
     (state: AppState) => state.cart,
     (cart) => cart.items
   );
   ```

4. **Effects:**
   - Handle side effects such as API calls across MFEs.
   - Example:
   ```typescript
   export class CartEffects {
     addToCart$ = createEffect(() => this.actions$.pipe(
       ofType(addToCart),
       switchMap(action => this.cartService.addToCart(action.product).pipe(
         map(() => addToCartSuccess()),
         catchError(() => of(addToCartFailure()))
       ))
     ));
     constructor(private actions$: Actions, private cartService: CartService) {}
   }
   ```

### **State Management Implementation Steps for MFEs:**

1. **Install NgRx:**
   ```bash
   npm install @ngrx/store @ngrx/effects @ngrx/entity @ngrx/store-devtools
   ```

2. **Configure the store in `app.module.ts` of the host application:**
   ```typescript
   import { StoreModule } from '@ngrx/store';
   import { cartReducer } from './state/cart.reducer';

   @NgModule({
     imports: [StoreModule.forRoot({ cart: cartReducer })]
   })
   export class AppModule {}
   ```

3. **Add feature module store in each MFE:**
   ```typescript
   StoreModule.forFeature('cart', cartReducer);
   ```

4. **Using store in MFE components:**
   ```typescript
   constructor(private store: Store) {}
   this.store.dispatch(addToCart({ product: selectedProduct }));
   this.store.select(selectCartItems).subscribe(cartItems => console.log(cartItems));
   ```

5. **Sharing state across MFEs:**
   - Use module federation to share NgRx store instance.
   - Ensure proper isolation of states per MFE while accessing shared state as needed.
   - Example in host application:
   ```typescript
   StoreModule.forRoot({}, { runtimeChecks: { strictStateImmutability: false } });
   ```

6. **Syncing state changes across MFEs:**
   - Utilize shared actions and selectors to synchronize data.
   - Example:
   ```typescript
   this.store.dispatch(addToCart({ product: newProduct }));
   this.store.select(selectCartItems).subscribe(cartItems => console.log(cartItems));
   ```

---

## Conclusion

By implementing Micro Frontend Architecture with NgRx, this Ecommerce App achieves scalability, maintainability, and flexibility, ensuring seamless user experiences and efficient development workflows.



---

## Cross-App Communication Patterns

Effective communication between micro frontends is crucial for maintaining consistency and synchronization across the entire application. Below are the common communication patterns used across MFEs:

### 1. State Sharing Using NgRx
Utilize a shared NgRx store to hold the global state accessible across all MFEs. Actions dispatched from one MFE are listened to by others.

**Example:**
```typescript
this.store.dispatch(addToCart({ product: selectedProduct }));
this.store.select(selectCartItems).subscribe(cartItems => {
  console.log(cartItems);
});
```

### 2. Custom Event Emitters
Angular's EventEmitter allows micro frontends to communicate by emitting and subscribing to custom events. Useful for decoupling MFEs and reducing dependencies.

**Example:**
```typescript
import { EventEmitter } from '@angular/core';
export const cartUpdated = new EventEmitter<any>();
cartUpdated.emit({ item: 'Product A' });
cartUpdated.subscribe(data => console.log(data));
```

### 3. API-based Communication
Each MFE communicates with the backend directly to fetch and update data. Requires consistent authentication and authorization mechanisms.

**Example:**
```typescript
this.http.get('/api/cart').subscribe(response => {
  console.log(response);
});
```

### 4. Message Bus Pattern
A centralized event bus or messaging system (e.g., RxJS Subject) is used to broadcast and listen for events.

**Example:**
```typescript
import { Subject } from 'rxjs';
const messageBus = new Subject<string>();
messageBus.subscribe(message => console.log(message));
messageBus.next('Product added to cart');
```

### 5. Local Storage for Cross-MFE Data Sharing
Use browser storage (localStorage/sessionStorage) to store state that needs to persist across MFEs. Ensure data synchronization by listening to storage events.

**Example:**
```typescript
localStorage.setItem('cart', JSON.stringify(cartData));
window.addEventListener('storage', (event) => {
  if (event.key === 'cart') {
    console.log('Cart updated:', event.newValue);
  }
});
```

### 6. URL-based Communication
Pass necessary data through query parameters or URL fragments. Allows direct bookmarking and sharing of states.

**Example:**
```typescript
this.router.navigate(['/cart'], { queryParams: { productId: 123 }});
```

### 7. WebSockets for Real-time Data Sync
Enables real-time updates across MFEs without constant polling.

**Example:**
```typescript
const socket = new WebSocket('wss://api.example.com/updates');
socket.onmessage = (event) => {
  console.log('Received update:', event.data);
};
```

### Choosing the Right Communication Pattern

| Use Case                 | Recommended Pattern           |
|--------------------------|-------------------------------|
| Global state management  | NgRx Store                     |
| Decoupled communication  | Custom Event Emitters          |
| Persistent data sharing  | Local Storage                  |
| Real-time updates        | WebSockets                     |
| API-based operations     | HTTP Calls                     |

---

## Docker Containerization

### Steps to Containerize 5 Micro Frontends

#### Create Dockerfile for each Micro Frontend

**Example Dockerfile:**
```dockerfile
FROM node:18-alpine AS build
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
CMD ["nginx", "-g", "daemon off;"]
```

**Build and tag Docker images:**
```bash
docker build -t product-mfe ./product
docker build -t cart-mfe ./cart
docker build -t checkout-mfe ./checkout
docker build -t user-mfe ./user
docker build -t admin-mfe ./admin
```

**Run containers locally:**
```bash
docker run -d -p 4201:80 product-mfe
docker run -d -p 4202:80 cart-mfe
docker run -d -p 4203:80 checkout-mfe
docker run -d -p 4204:80 user-mfe
docker run -d -p 4205:80 admin-mfe
```

---

## Kubernetes Deployment

### Steps to Deploy Micro Frontends on Kubernetes

#### Create Kubernetes Deployment YAML files for each MFE

**Example product-mfe-deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: product-mfe
spec:
  replicas: 2
  selector:
    matchLabels:
      app: product-mfe
  template:
    metadata:
      labels:
        app: product-mfe
    spec:
      containers:
      - name: product-mfe
        image: product-mfe:latest
        ports:
        - containerPort: 80
```

**Create Kubernetes Service YAML files for each MFE**

**Example product-mfe-service.yaml:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: product-mfe-service
spec:
  selector:
    app: product-mfe
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  type: LoadBalancer
```

**Deploy to Kubernetes cluster:**
```bash
kubectl apply -f product-mfe-deployment.yaml
kubectl apply -f product-mfe-service.yaml
```

**Scale the deployment:**
```bash
kubectl scale deployment product-mfe --replicas=3
```

**Check deployment and service status:**
```bash
kubectl get pods
kubectl get services
```

---

## Conclusion

By implementing Micro Frontend Architecture with NgRx, this Ecommerce App achieves scalability, maintainability, and flexibility, ensuring seamless user experiences and efficient development workflows.

