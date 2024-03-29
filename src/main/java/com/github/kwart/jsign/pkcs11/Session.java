/*
 * Copyright (c) 2003, 2011, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.github.kwart.jsign.pkcs11;

import java.lang.ref.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import java.security.*;

import sun.security.pkcs11.wrapper.*;

/**
 * A session object. Sessions are obtained via the SessionManager,
 * see there for details. Most code will only ever need one method in
 * this class, the id() method to obtain the session id.
 *
 * @author  Andreas Sterbenz
 * @since   1.5
 */
final class Session implements Comparable<Session> {

    // time after which to close idle sessions, in milliseconds (3 minutes)
    private final static long MAX_IDLE_TIME = 3 * 60 * 1000;

    // token instance
    final Token token;

    // session id
    private final long id;

    // number of objects created within this session
    private final AtomicInteger createdObjects;

    // time this session was last used
    // not synchronized/volatile for performance, so may be unreliable
    // this could lead to idle sessions being closed early, but that is harmless
    private long lastAccess;

    private final SessionRef sessionRef;

    Session(Token token, long id) {
        this.token = token;
        this.id = id;
        createdObjects = new AtomicInteger();
        id();
        sessionRef = new SessionRef(this, id, token);
    }

    public int compareTo(Session other) {
        if (this.lastAccess == other.lastAccess) {
            return 0;
        } else {
            return (this.lastAccess < other.lastAccess) ? -1 : 1;
        }
    }

    boolean isLive(long currentTime) {
        return currentTime - lastAccess < MAX_IDLE_TIME;
    }

    long idInternal() {
        return id;
    }

    long id() {
        if (token.isPresent(this.id) == false) {
            throw new ProviderException("Token has been removed");
        }
        lastAccess = System.currentTimeMillis();
        return id;
    }

    void addObject() {
        int n = createdObjects.incrementAndGet();
        // XXX update statistics in session manager if n == 1
    }

    void removeObject() {
        int n = createdObjects.decrementAndGet();
        if (n == 0) {
            token.sessionManager.demoteObjSession(this);
        } else if (n < 0) {
            throw new ProviderException("Internal error: objects created " + n);
        }
    }

    boolean hasObjects() {
        return createdObjects.get() != 0;
    }

    void close() {
        if (hasObjects()) {
            throw new ProviderException(
                "Internal error: close session with active objects");
        }
        sessionRef.dispose();
    }
}

/*
 * NOTE: Use PhantomReference here and not WeakReference
 * otherwise the sessions maybe closed before other objects
 * which are still being finalized.
 */
final class SessionRef extends PhantomReference<Session>
        implements Comparable<SessionRef> {

    private static ReferenceQueue<Session> refQueue =
        new ReferenceQueue<Session>();

    private static Set<SessionRef> refList =
        Collections.synchronizedSortedSet(new TreeSet<SessionRef>());

    static ReferenceQueue<Session> referenceQueue() {
        return refQueue;
    }

    static int totalCount() {
        return refList.size();
    }

    private static void drainRefQueueBounded() {
        while (true) {
            SessionRef next = (SessionRef) refQueue.poll();
            if (next == null) break;
            next.dispose();
        }
    }

    // handle to the native session
    private long id;
    private Token token;

    SessionRef(Session session, long id, Token token) {
        super(session, refQueue);
        this.id = id;
        this.token = token;
        refList.add(this);
        // TBD: run at some interval and not every time?
        drainRefQueueBounded();
    }

    void dispose() {
        refList.remove(this);
        try {
            if (token.isPresent(id)) {
                token.p11.C_CloseSession(id);
            }
        } catch (PKCS11Exception e1) {
            // ignore
        } catch (ProviderException e2) {
            // ignore
        } finally {
            this.clear();
        }
    }

    public int compareTo(SessionRef other) {
        if (this.id == other.id) {
            return 0;
        } else {
            return (this.id < other.id) ? -1 : 1;
        }
    }
}
