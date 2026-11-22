import { describe, expect, it } from 'vitest';

import { barOption, countEntries, doughnutOption, hBarOption, lineOption } from '@/utils/charts';

describe('lineOption', () => {
  it('按系列生成折线配置', () => {
    const option = lineOption({
      categories: ['2026-11-20', '2026-11-21'],
      series: [
        { name: 'yara', data: [1, 2] },
        { name: 'clamav', data: [0, 3], color: '#ff0000' },
      ],
      yName: '命中',
    });
    expect(option.xAxis).toMatchObject({ type: 'category', data: ['2026-11-20', '2026-11-21'] });
    expect((option.series as unknown[]).length).toBe(2);
    expect(option.color).toEqual(['#1f5fbf', '#ff0000']);
  });

  it('类目较少时显示数据点，较多时隐藏以减少噪声', () => {
    const few = lineOption({ categories: ['a'], series: [{ name: 's', data: [1] }] });
    expect((few.series as { showSymbol: boolean }[])[0].showSymbol).toBe(true);
    const many = lineOption({
      categories: Array.from({ length: 20 }, (_, index) => `d${index}`),
      series: [{ name: 's', data: Array.from({ length: 20 }, () => 1) }],
    });
    expect((many.series as { showSymbol: boolean }[])[0].showSymbol).toBe(false);
  });
});

describe('doughnutOption', () => {
  it('过滤 0 值项', () => {
    const option = doughnutOption([
      ['严重', 3],
      ['高', 0],
    ]);
    const data = (option.series as { data: { name: string }[] }[])[0].data;
    expect(data).toHaveLength(1);
    expect(data[0].name).toBe('严重');
  });

  it('全部为 0 时数据为空（由组件展示空态）', () => {
    const option = doughnutOption([['a', 0]]);
    expect((option.series as { data: unknown[] }[])[0].data).toHaveLength(0);
  });
});

describe('barOption / hBarOption', () => {
  it('柱状图保持类目顺序', () => {
    const option = barOption(['2024', '2025'], [3, 5]);
    expect(option.xAxis).toMatchObject({ data: ['2024', '2025'] });
    expect((option.series as { data: number[] }[])[0].data).toEqual([3, 5]);
  });

  it('横向柱状图按数值升序（ECharts 从下往上画）', () => {
    const option = hBarOption([
      ['a', 5],
      ['b', 1],
    ]);
    expect((option.yAxis as { data: string[] }).data).toEqual(['b', 'a']);
  });
});

describe('countEntries', () => {
  it('按数值降序转数组', () => {
    expect(countEntries({ a: 1, b: 9, c: 5 })).toEqual([
      ['b', 9],
      ['c', 5],
      ['a', 1],
    ]);
  });

  it('空对象返回空数组', () => {
    expect(countEntries({})).toEqual([]);
  });
});
