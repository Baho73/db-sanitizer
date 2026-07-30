-- Демо-база «кадры и заявки»: 14 таблиц, вложенные и композитные FK,
-- мягкая связь по ИНН без констрейнта, враждебные случаи §7. (M-DEMO-DB)
CREATE SCHEMA IF NOT EXISTS hr;

CREATE TABLE hr.regions (
    id      serial PRIMARY KEY,
    name    varchar(80) NOT NULL
);

CREATE TABLE hr.departments (
    id        serial PRIMARY KEY,
    name      varchar(120) NOT NULL,
    region_id int NOT NULL REFERENCES hr.regions(id)
);

CREATE TABLE hr.positions (
    id     serial PRIMARY KEY,
    title  varchar(120) NOT NULL,
    grade  varchar(8)   NOT NULL          -- чувствительная категория малой кардинальности (§5.6)
);

CREATE TABLE hr.employees (
    id              serial PRIMARY KEY,
    tab_no          int  NOT NULL UNIQUE,
    last_name       varchar(60)  NOT NULL,
    first_name      varchar(60)  NOT NULL,
    middle_name     varchar(60),
    birth_date      date NOT NULL,
    inn             varchar(12)  NOT NULL UNIQUE,   -- естественный ключ, мягкая связь
    snils           varchar(11)  NOT NULL,
    passport_series varchar(4)   NOT NULL,
    passport_number varchar(6)   NOT NULL,
    phone           varchar(20)  NOT NULL,
    email           varchar(120) NOT NULL UNIQUE,   -- UNIQUE email (§7)
    salary          numeric(12,2) NOT NULL,
    f_115           int NOT NULL,                    -- неинформативное имя (§7)
    attrs           jsonb,                           -- ПДн внутри jsonb (§7)
    dept_id         int NOT NULL REFERENCES hr.departments(id),
    position_id     int NOT NULL REFERENCES hr.positions(id),
    hire_date       date NOT NULL
);

CREATE TABLE hr.addresses (
    id          serial PRIMARY KEY,
    employee_id int NOT NULL REFERENCES hr.employees(id),
    addr_text   varchar(300) NOT NULL               -- грязная адресная строка (§3.2)
);

CREATE TABLE hr.documents (
    id          serial PRIMARY KEY,
    employee_id int NOT NULL REFERENCES hr.employees(id),
    doc_type    varchar(20) NOT NULL,
    doc_number  varchar(30) NOT NULL
);

CREATE TABLE hr.contractors (
    id     serial PRIMARY KEY,
    name   varchar(160) NOT NULL,
    inn    varchar(12)  NOT NULL,                    -- мягкая связь с contracts.contractor_inn
    kpp    varchar(9)   NOT NULL,
    ogrn   varchar(15)  NOT NULL,
    city   varchar(200) NOT NULL                     -- имя врёт: лежат полные адреса (§7)
);

CREATE TABLE hr.contracts (
    id             serial PRIMARY KEY,
    number         varchar(30) NOT NULL,
    contractor_inn varchar(12) NOT NULL,             -- FK НЕ объявлен: мягкая связь по ИНН
    signed_by      int NOT NULL REFERENCES hr.employees(id),
    amount         numeric(14,2) NOT NULL,
    contract_date  date NOT NULL
);

CREATE TABLE hr.contract_items (
    contract_id int NOT NULL REFERENCES hr.contracts(id),
    item_no     int NOT NULL,
    descr       varchar(200) NOT NULL,
    qty         int NOT NULL,
    PRIMARY KEY (contract_id, item_no)
);

CREATE TABLE hr.shipments (                          -- композитный FK (§7)
    id          serial PRIMARY KEY,
    contract_id int NOT NULL,
    item_no     int NOT NULL,
    shipped_at  date NOT NULL,
    FOREIGN KEY (contract_id, item_no) REFERENCES hr.contract_items(contract_id, item_no)
);

CREATE TABLE hr.tickets (
    id          serial PRIMARY KEY,
    employee_id int NOT NULL REFERENCES hr.employees(id),
    subject     varchar(200) NOT NULL,
    body_text   text NOT NULL                        -- свободный текст с ПДн
);

CREATE TABLE hr.ticket_comments (
    id          serial PRIMARY KEY,
    ticket_id   int NOT NULL REFERENCES hr.tickets(id),
    author_id   int NOT NULL REFERENCES hr.employees(id),
    comment_text varchar(400) NOT NULL               -- склейки «ФИО, тел. ...» (§7)
);

CREATE TABLE hr.payroll (
    id          serial PRIMARY KEY,
    employee_id int NOT NULL REFERENCES hr.employees(id),
    pay_month   date NOT NULL,
    amount      numeric(12,2) NOT NULL
);

CREATE TABLE hr.audit_log (
    id          serial PRIMARY KEY,
    employee_id int REFERENCES hr.employees(id),
    action      varchar(40) NOT NULL,
    ts          timestamptz NOT NULL
);
