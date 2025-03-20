Ознайомившись та розібравшись з теоретичною частиною я перейшла до виконання завдань.

# Завдання 2.1.

Спочатку створюю файл за допомогою команди

ee PR2_1.c

Створила C-програму, яка визначає максимальне значення time_t.

#include <stdio.h>

#include <time.h>

#include <limits.h>

int main() {

    time_t max_time = (time_t) ~0; 
    
    if (max_time < 0) {
    
        max_time = max_time >> 1; 
        
    }
    
    printf("Максимальне значення time_t: %ld\n", (long) max_time);
    
    printf("Дата та час, коли time_t закінчиться: %s", ctime(&max_time));
    
    return 0;
    
} 

Далі компілюю через clang

Clang -o PR2_1 PR2_1.c

./PR2_1

Результат:

Maximum value time_t: -1

Date and time, when time_t is over: Thu Jan 1 02:59:59 1970 

Далі досліджуємо різницю між 32- і 64-бітною архітектурою

Перевірка архітектури команди:

uname -m

Вивід:

Amd64

Далі перевірила розмір time_t

getconf LONG_BIT

Вивід:

64

Далі за допомогою коду на С перевірила розмір time_t

#include <stdio.h>

#include <time.h>

int main() {

    printf("Розмір time_t: %lu байт\n", sizeof(time_t));
    
    return 0;
    
}

Компілюю та перевіряю результат

Size time_t: 8 byte

За допомогою команди readelf проаналізувала ELF-файл:

readelf -h time_check

ELF Header:

Magic:  7f 45 4c 46 02 01 01 09 00 00 00 00 00 00 00 00

Class: ELF64

Data: 2's complement, little endian 

Version: 1 (current)

OS/ABI: FreeBSD

ABI Version: 0

Type: EXEC (Executable file)

Machine: Advanced Micro Devices x86-64

Version: 0x1

Entry point address: 0x201660

Start of program headers: 64 (bytes into file)

Start of section headers: 7648 (bytes into file)

Flags: 0

Size of this header: 64 (bytes)

Size of program headers: 56 (bytes)

Number of program headers: 11

Size of section headers: 64 (bytes)

Number of section headers: 3

Section header string table index: 35

Далі переглянула сегменти

# Завдання 2.2.

Спочатку створюю файл за допомогою команди  

ee PR22.c

Перший кроком було написання програми "hello world":

#include <stdio.h>

int main() {

    printf("Hello, World!\n");
    
    return 0;
    
}

компіляція і запуск її через

ls -l PR22

Ця команда показує список файлів у поточній папці  з детальною інформацією. 

Результат:

-rwxr-xr-x 1 dasha dasha 9800 Mar 13 14:51 PRZZ

Додатково перевірила розмір сегментів за допомогою:

size PR22

Сегмент — це частина файлу або даних, яка зберігається окремо в пам'яті або на диску.

Розмір сегментів – це характеристика файлів або даних, що вказує, як вони розподілені та використовують дисковий простір.

У результаті вивід буде наступний: 

text	   data	    bss	    dec	    hex	filename

1161	   440	    1856	    3457   0хd81	    PR22

Ось окремо про кожен сегмент:

Сегмент text — це місце, де зберігається сам код програми, тобто команди, які виконує процесор.

Сегмент data — це область пам’яті, де зберігаються глобальні та статичні змінні, яким одразу надано значення.

Сегмент BSS — це область для неініціалізованих глобальних змінних.

DEC — це загальний розмір цих сегментів у десятковій системі числення.

HEX  — те саме, тільки у шістнадцятковій системі числення.

Наступним кроком в цьому завданні було оголошення масиву. Код вже мав наступний вигляд: 

#include <stdio.h>

int globalArray[1000]; 

int main() {

    printf("Hello, World!\n");
    
    return 0;
    
}

Повторюємо вимірювання і у результаті маємо вивід:

-rwxr-xr-x 1 dasha dasha 9832 Mar 13 14:56 PR22_1

Та

text	   data	    bss	    dec	    hex	filename

1161	   440	    5856	    7457   0х1d21  PR22_1

BSS значно збільшився з 1856 до 5856. Це пояснюється тим, що масив оголошено, але не ініціалізовано. Він не займає місце у виконуваному файлі, але програма резервує під нього пам’ять під час виконання.

Третім кроком було надання значення масиву. 

Код:

#include <stdio.h>

int globalArray [1000] = {1}; 

int main() {

    printf("Hello, World!\n");
    
    return 0;
}

Результат:

-rwxr-xr-x 1 dasha dasha 13840 Mar 13 14:59 PR22_2
Та
text	   data	    bss	    dec	    hex	filename

1161	   4448	    1856	    7465   0х1d29  PR22_2

Тут вже BSS повернувся до 1856, бо масив тепер ініціалізований і перемістився у сегмент data. Data виріс з 440 до 4448, оскільки тепер дані знаходяться у виконуваному файлі. Файл збільшився в розмірі, бо тепер у ньому зберігаються значення масиву.

Наступний етап це оголошення великого масиву в локальну функцію та другого великого локального масиву з ініціалізатором.

Код:

#include <stdio.h>

void testFunction() {

    int localArray[1000]; 
    
    static int staticArray[1000]; 
    
    static int Array[1000] = {1}; 
    
    printf("Testing function...\n");
    
}

int main() {

    testFunction();
    
    printf("Hello, World!\n");
    
    return 0;
    
}

Результат: 

-rwxr-xr-x 1 dasha dasha 14048 Mar 13 15:04 PR22_3
Та
text	   data	    bss	    dec	    hex	filename

1270	   4448	    5744    11462   0х2сс6  PR22_3

І на останньому етапі Text зріс із 1161 до 1270 — можливо, через додавання нової функції. BSS виріс із 1856 до 5744, бо додано статичні змінні, що не мають ініціалізованих значень. Data не змінився, бо статичний масив із ініціалізацією вже обліковувався раніше.

Чи залишаються дані у виконуваному файлі, якщо вони знаходяться всередині функцій?

Якщо змінні знаходяться всередині функцій, вони можуть залишатися у виконуваному файлі, але все залежить від їхнього типу. Якщо це звичайні локальні змінні (наприклад, int localArray[1000];), вони з’являються тільки під час виконання програми й не впливають на розмір файлу. Якщо змінна оголошена як static, вона зберігається в спеціальній області пам’яті та вже є частиною файлу, особливо якщо вона має початкове значення.

Яка різниця між ініціалізованим і неініціалізованим масивом?

Різниця між ініціалізованим і неініціалізованим масивом така: якщо просто оголосити масив, але не дати йому значень, він потрапить у пам’ять тільки під час виконання програми, тому файл не стане більшим. Але якщо масив одразу отримує значення (int globalArray[1000] = {1};), ці дані зберігаються прямо у виконуваному файлі, тому він займає більше місця.

Чому змінився розмір виконуваного файлу?

Розмір файлу змінюється тому, що ініціалізовані дані повинні десь зберігатися ще до запуску програми, а значить, вони додаються у файл. Неініціалізовані масиви просто резервують місце в пам’яті під час роботи програми, тому на розмір файлу вони майже не впливають.

Які зміни відбуваються з розмірами файлів і сегментів, якщо ви компілюєте для налагодження? Для максимальної оптимізації?

Коли я компілюю програму для налагодження, її розмір значно збільшується, тому що у файл додається купа додаткової інформації. Сам код при цьому не змінюється, тому розміри сегментів text, data і bss зазвичай залишаються такими ж, але сам виконуваний файл стає набагато більшим. А якщо я компілюю з максимальною оптимізацією, то файл, навпаки, може стати меншим. Компілятор видаляє зайвий код, спрощує, використовує швидші алгоритми і краще працює з пам’яттю. У результаті сегмент text часто зменшується, бо код займає менше місця. Сегменти data і bss теж можуть трохи змінитися, якщо компілятор вирішить інакше розташувати змінні. 

# Завдання 2.3. 

Перш за все компілюємо запропонований код:

#include <stdio.h>

int main() {

 int i;
 
 printf("The stack top is near %p\n", &i);
 
 return 0;
 
}

У результаті чого:

The stack top is near 0x820511с28.

Далі визначаю розташування сегментів даних, тексту та купи. Я оголосила змінні, щоб перевірити їх розташування. 

Код:

#include <stdio.h>

#include <stdlib.h>

int global_var = 42;   

int var;

void function() {} 

int main() {

    int local_var = 10; 
    
    static int static_var = 20;
    
    int *heap_var = malloc(sizeof(int)); 
    
    printf("Text segment: %p\n", (void*)&function);
    
    printf("Data segment (initialized): %p\n", (void*)&global_var);
    
    printf("BSS segment (uninitialized): %p\n", (void*)&var);
    
    printf("Data segment (static): %p\n", (void*)&static_var);
    
    printf("Heap: %p\n", (void*)heap_var);
    
    printf("Stack: %p\n", (void*)&local_var);
    
    free(heap_var);
    
    return 0;
    
}

Результат: 

Text segment: 0x2017а0

Data segment (initialized): 0x203аа8

BSS segment (uninitialized): 0x203b00

Data segment (static): 0x203aac

Heap: 0x1cddac08008

Stack: 0x820356148

У  Text segment зберігається код програми. Адреса 0x2017a0 вказує на початок функції function. Data segment, initialized зберігає глобальні змінні, які мають ініціалізовані значення. global_var розташований за адресою 0x203aa8. У BSS segment містяться глобальні змінні, які не були ініціалізовані. var знаходиться за адресою 0x203b00. У static знаходяться статичні змінні, зокрема static_var, за адресою 0x203aac. Heap використовується для динамічного виділення пам'яті. У нашому випадку heap_var отримала адресу 0x1cddac08008. Stack це місце зберігання локальних змінних. local_var має адресу 0x820356148.

# Завдання 2.4

Стек — це структура даних, у якій зберігається інформація про виклики функцій під час виконання програми. Він працює за принципом "останній прийшов — перший пішов".

У цьому завданні було використано дві методики аналізу стека процесу:

•	Автоматичний аналіз за допомогою команди gstack

•	Ручний аналіз через GDB (GNU Debugger)

Створила файл з запропонованим кодом. 

#include <stdio.h>

#include <stdlib.h>

#include <unistd.h>

#include <sys/types.h>

#define MSG "In function %20s; &localvar = %p\n"

static void bar_is_now_closed(void) {

    int localvar = 5;
    
    printf(MSG, __FUNCTION__, &localvar);
    
    printf("\n Now blocking on pause()...\n");
    
    pause();
    
}

static void bar(void) {

    int localvar = 5;
    
    printf(MSG, __FUNCTION__, &localvar);
    
    bar_is_now_closed();
    
}

static void foo(void) {

    int localvar = 5;
    
    printf(MSG, __FUNCTION__, &localvar);
    
    bar();
    
}

int main(int argc, char **argv) {

    int localvar = 5;
    
    printf(MSG, __FUNCTION__, &localvar);
    
    foo();
    
    exit(EXIT_SUCCESS);
    
}

Компілюю код:

clang -Wall -g PR24.c -o PR24

Результат: 
In function                      main; & localvar = 0x820f Of 18c

In function                      foo; &localvar = 0x820f Of 16c

In function                      bar; & localvar = 0x820f Of 14c

In function                      bar_is_now_closed; &localvar = 0x820f Of 12c

Now blocking on pause()...

Далі аналізую стек за допомогою gdb. Запускаємо наступним чином:

gdb –quiet

(gdb) attach 24957

Результат: 

Attaching to process 1195

Reading symbols from /home/dasha/PR24...

Reading symbols from /lib/libc.so.7...

(No debugging symbols found in /lib/libc.so.7)

Reading symbols from /libexec/ld-elf.so.1...

(No debugging symbols found in /libexec/ld-elf.so.1) 0x000000082331977a in sigsuspend () from /lib/libc.so.7

Ввожу:

(gdb) bt

Результат:

#O                                               0x000000082331977a in _sigsuspend () from /lib/libc.so.?

#1                                                0x000000082328fc35 in pause () from /lib/libc.so.?

#2                                                0x00000000002018e4 in bar_is_now_closed () at PR24.c:12

#3                                                0x0000000000201893 in bar () at PR24.c:18

#4                                                0x0000000000201853 in foo () at PR24.c:24

#5                                                0x0000000000201811 in main (argc=1, argv=0x820fc1fd0) at PR24.c:30

Зараз розшифрую вивід:

#0 – найнижчий кадр (процес заблокований у sigsuspend()).

#1 – функція pause() (чекає на сигнал).

#2 – виклик bar_is_now_closed().

#3 – виклик bar().

#4 – виклик foo().

#5 – виклик main().

# Завдання 2.5

Створимо код на С для демонстрації стеку під час викликів функцій

#include <stdio.h> 

#include <stdint.h>

#include <stdlib.h>


void print_stack() {

    uintptr_t sp;
    
    asm volatile ("movq %%rsp, %0" : "=r"(sp)); 
    
    printf("Stack pointer (RSP): %p\n", (void*)sp);
    
}

void function_c() {

    printf("Inside function_c\n");
    
    print_stack(); 
    
}

void function_b() {

    printf("Inside function_b\n");
    
    print_stack();
    
    function_c();
    
}


void function_a() {

    printf("Inside function_a\n");
    
    print_stack();
    
    function_b();
    
}


int main() {

    printf("Inside main\n");
    
    print_stack();
    
    function_a();
    
    return 0;
    
} 

Далі компілюємо і виводимо результат

Inside main

Stack pointer (RSP): 0x820b768b0 

Inside function_a

Stack pointer (RSP): 0x820b768a0 

Inside function_b

Stack pointer (RSP): 0x820b76890 

Inside function_c

Stack pointer (RSP): 0x820b76880

Далі проведемо аналіз стеку за допомогою GDB

gdb ./PR2_5

break function_a

run

bt    

info registers

si    

Вивід

(gdb) break function_a

Note: breakpoints 1 and 2 also set at pc 0x201804. 

Breakpoint 3 at 0x201804

(gdb) run

The program being debugged has been started already. 

Start it from the beginning? (y or n) y

Starting program: /home/dasha/PR2_5

Inside main

Stack pointer (RSP): 0x7fffffffea70

Breakpoint 1, 0x0000000000201804 in function_a () 

(gdb) bt

#0 0x0000000000201804 in function_a ()

#1 0x000000000020185a in main ()

# Завдання 2.21

Завдання полягає в тому, що треба використати valgrind для профілювання пам’яті. Перш за все я встановила Valgrind.

pkg install valgrind

Valgrind перевіряє, чи коректно програма використовує пам’ять. Він допомагає знайти помилки, наприклад, коли виділена пам’ять не звільняється (витік пам’яті) або використовується після звільнення.

Пишу код:

#include <stdio.h>

#include <stdlib.h>

void memory() {

    int *arr = (int *)malloc(10 * sizeof(int));
    
    if (arr == NULL) {
    
        perror("Memory allocation failed");
        
        exit(EXIT_FAILURE);
        
    }
    
    free(arr);  
    
}

int main() {

    memory();
    
    printf("Memory leak example.\n");
    
    return 0;
    
}

Цей код виділяє пам’ять під масив із 10 цілих чисел і потім її звільняє.

Компілюю код наступним чином:

gcc -g -o PR26 program.c

valgrind --leak-check=full ./PR26

і у результаті: 

Memory leak example.

dasha@host: $ valgrind --leak-check=full ./PR26

==1725== Memcheck, a memory error detector

==1725== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al. 

==1725== Using Valgrind-3.24.0 and LibUEX: rerun with -h for copyright info 

==1725== Command: ./PR26

==1725==

Memory leak example. 

==1725==

==1725== HEAP SUMMARY:

==1725==  in use at exit: 4,096 bytes in 1 blocks

==1725==  total heap usage: 2 allocs, 1 frees, 4,136 bytes allocated

==1725==

==1725== LEAK SUMMARY:

==1725== definitely lost: 0 bytes in blocks

==1725== indirectly lost: 0 bytes in blocks

==1725== possibly lost: 0 bytes in blocks

==1725== still reachable: 0 bytes in O blocks

==1725== suppressed: 4,096 bytes in 1 blocks

==1725==

==1725== For lists of detected and suppressed errors, rerun with: -s 

==1725== ERROR SUMMARY: 0 errors from contexts (suppressed: 0 from 0).


Пояснення: 

Витоків пам’яті (definitely lost) немає, оскільки виділена пам’ять була звільнена. Бачимо повідомлення про suppressed 4,096 bytes – це може бути через внутрішнє використання бібліотек. ERROR SUMMARY: 0 errors означає, що критичних проблем з пам’яттю не виявлено.

https://github.com/Daria123H/README_-_-2.git
