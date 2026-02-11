// Coordinator Service Worker
//
// Implemented in JavaScript rather than Rust to avoid WASM compilation
// latency on Service Worker startup (browsers may kill and restart SWs at any
// time). The coordinator only does lightweight coordination (task tracking,
// JSON parsing, promise resolution) which doesn't benefit from WASM.

const tasks = new Map(); // task_id -> { expected, completed, resolver, results }

export function setupCoordinator() {
   self.addEventListener('install', (_event) => {
       self.skipWaiting();
   });

   self.addEventListener('activate', (event) => {
       event.waitUntil(self.clients.claim());
   });

   self.addEventListener('fetch', (event) => {
       const url = new URL(event.request.url);
       const pathname = url.pathname;

       if (!pathname.startsWith('/__wasm_par__/')) {
           return;
       }

       const response = handleRequest(event.request, pathname);
       if (response) {
           event.respondWith(response);
       }
   });

}

function handleRequest(request, pathname) {
    const method = request.method;

    // (from sync_executor) ping to check that the coordinator is up
    if (method === 'GET' && pathname === '/__wasm_par__/ping') {
        return Promise.resolve(jsonResponse(200, {}));
    }

    // (from sync_executor) Register a new task
    if (method === 'POST' && pathname === '/__wasm_par__/task') {
        return request.json().then(body => {
            const { task_id, num_chunks } = body;
            tasks.set(task_id, { expected: num_chunks, completed: 0, resolver: null, results: [] });
            return jsonResponse(200, {});
        }).catch(e => jsonResponse(500, { message: e.toString() }));
    }

    // (from worker) Signal that a task is done
    if (method === 'POST' && pathname === '/__wasm_par__/done') {
        return request.json().then(body => {
            const { task_id, chunk_id, result } = body;
            const task = tasks.get(task_id);
            if (!task) {
                return jsonResponse(404, { message: 'Task not found' });
            }
            task.results.push({ chunk_id, result })
            task.completed += 1;

            // Return early on error
            if (result.Err !== undefined && task.resolver) {
                task.resolver(jsonResponse(200, { results: task.results }));
                tasks.delete(task_id);
                return jsonResponse(200, {});
            }

            if (task.completed >= task.expected && task.resolver) {
                task.resolver(jsonResponse(200, { results: task.results }));
                tasks.delete(task_id);
            }
            return jsonResponse(200, {});
        }).catch(e => jsonResponse(500, { message: e.toString() }));
    }

    // (from sync executor) block on a task until completion
    if (method === 'GET' && pathname.startsWith('/__wasm_par__/wait/')) {
        const task_id = parseInt(pathname.split('/').pop(), 10);
        const task = tasks.get(task_id);

        if (!task) {
            return Promise.resolve(jsonResponse(404, { message: 'Task not found' }));
        }

        // Return early if the task already completed
        if (task.completed >= task.expected) {
            tasks.delete(task_id);
            return Promise.resolve(jsonResponse(200, { results: task.results }));
        }

        return new Promise(resolve => {
            task.resolver = resolve;
        });
    }

    // (from sync executor) cancel a registered task
    if (method === 'GET' && pathname.startsWith('/__wasm_par__/cancel/')) {
        const task_id = parseInt(pathname.split('/').pop(), 10);
        const task = tasks.get(task_id);

        if (!task) {
            return Promise.resolve(jsonResponse(404, { message: 'Task not found' }));
        }

        tasks.delete(task_id);
        return Promise.resolve(jsonResponse(200, {}));
    }


    return Promise.resolve(jsonResponse(404, { message: 'Not found' }));
}

function jsonResponse(status, body) {
    return new Response(JSON.stringify(body), {
        status: status,
        headers: { 'Content-Type': 'application/json' }
    });
}
