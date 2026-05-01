#include <gtest/gtest.h>
#include <pthread.h>
#include <vector>
extern "C" {
    #include "../imm/IntMemoryManager.h"
}


TEST (ImmGlobal, RequirementLimit)
{
    MemoryRequireKB (256);
    void *p = MemoryAllocate (100);
    ASSERT_NE (p, nullptr);

    IntMemoryRange *meta = (IntMemoryRange *)p - 1;
    EXPECT_EQ (meta->hex, IMM_HEX);
    
    cleanbit (p);
}

TEST (ImmInternal, Coalescing)
{
    void *po = MemoryAllocate (100);
    void *pt = MemoryAllocate (100);
    void *ptt = MemoryAllocate (100);
    
    ASSERT_NE (po, nullptr);
    ASSERT_NE (pt, nullptr);
    ASSERT_NE (ptt, nullptr);

    IntMemoryRange *mo = (IntMemoryRange *)po - 1;
    IntMemoryRange *mt = (IntMemoryRange *)pt - 1;
    size_t initial_free_size = mo->size;

    cleanbit (pt);
    cleanbit (po);

    EXPECT_TRUE (mo->free);
    EXPECT_GE (mo->size, 200 + BLOCK_SIZE);
    EXPECT_EQ (mo->next, ((IntMemoryRange *)ptt - 1));

    cleanbit (ptt);
}

TEST (ImmInternal, MagicTagVerification)
{
    size_t size = 128;

    void *ptr = MemoryAllocate (size);
    ASSERT_NE (ptr, nullptr);

    IntMemoryRange *meta = (IntMemoryRange *)ptr - 1;

    EXPECT_EQ (meta->hex, (uint32_t)IMM_HEX) << "Magic Tag 'IMMR' found." << std::endl;
    EXPECT_GE (meta->size, size) << "Block size in metadata, smaller than requested!" << std::endl;
    EXPECT_EQ (meta->free, 0) << "Block tagged as free, but it's already allocated!" << std::endl;

    cleanbit (ptr);
}

TEST (ImmAllocator, CallocIntegrity)
{
    size_t nmemb = 100;
    size_t size = sizeof (int);
    int *array = (int *)MemoryAllocateAndFillZero (nmemb, size);
    ASSERT_NE (array, nullptr);

    
    for (size_t i = 0; i < nmemb; ++i)
    {
        EXPECT_EQ (array[i], 0);
    }

    void *overflow = MemoryAllocateAndFillZero (SIZE_MAX, 2);
    EXPECT_EQ (overflow, nullptr);

    cleanbit (array);
}

TEST(ImmPool, Lifecycle) {
    size_t pool_size = 1024 * 1024; // 1MB
    IntMemoryPool* pool = MemoryPoolCreate(pool_size);
    ASSERT_NE(pool, nullptr);
    EXPECT_EQ(pool->total_size, pool_size);
    
    EXPECT_EQ(pool->base->hex, IMM_HEX);
    EXPECT_TRUE(pool->base->free);

    MemoryPoolAdd(pool, pool_size);
    EXPECT_EQ(pool->total_size, pool_size * 2);

    MemoryPoolCorrupt(pool);
}

void* thread_func(void* arg) {
    for(int i = 0; i < 100; ++i) {
        void* p = MemoryAllocate(64);
        if(p) cleanbit(p);
    }
    return nullptr;
}

TEST (ImmMultithread, ConcurrentAlloc) 
{
    const int NUM_THREADS = 10;
    pthread_t threads[NUM_THREADS];

    for(int i = 0; i < NUM_THREADS; ++i) {
        pthread_create(&threads[i], nullptr, thread_func, nullptr);
    }

    for(int i = 0; i < NUM_THREADS; ++i) {
        pthread_join(threads[i], nullptr);
    }
}